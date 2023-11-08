import {
  type ClientConfig,
  type QueryRequestOptions,
  type MutationRequestOptions,
  type ClientResponse,
  type GraphQLResponse,
  type ClientOperationErrorCodes,
  type ValidationResponseJSON,
  ResponseError,
  AuthorizationError,
  InputValidationError
} from "@fireboom/client";
import { utf8ArrayToStr } from './decoder'

type Headers = Record<string, string>
type Query = Record<string, any>
type Body = Record<string, any>
export type MiniappClientConfig = Omit<ClientConfig, 'customFetch'> & {
  requestImpl: (options: any) => void
  uploadImpl: (options: any) => void
}

export class Client {
  protected readonly baseHeaders: Headers = {}
  private extraHeaders: Headers = {}
  private csrfToken: string | undefined
  private userIsAuthenticated: boolean | undefined
  protected readonly csrfEnabled: boolean = true
  constructor(protected options: MiniappClientConfig) {
    this.baseHeaders = options.sdkVersion
      ? {
        'WG-SDK-Version': options.sdkVersion
      }
      : {}
    this.extraHeaders = { ...options.extraHeaders }
    this.csrfEnabled = options.csrfEnabled ?? true
  }

  public setBaseURL(url: string) {
    this.options.baseURL = url
  }

  public isAuthenticatedOperation(operationName: string) {
    return !!this.options.operationMetadata?.[operationName]?.requiresAuthentication
  }

  protected operationUrl(operationName: string) {
    return this.options.baseURL + '/operations/' + operationName
  }

  protected stringifyInput(input: any) {
    const encoded = JSON.stringify(input || {})
    return encoded === '{}' ? undefined : encoded
  }

  public setExtraHeaders(headers: Headers) {
    this.extraHeaders = {
      ...this.extraHeaders,
      ...headers
    }
  }

  public hasExtraHeaders() {
    return Object.keys(this.extraHeaders).length > 0
  }

  /**
   * setAuthorizationToken is a shorthand method for setting up the
   * required headers for token authentication.
   *
   * @param token Bearer token
   */
  public setAuthorizationToken(token: string) {
    this.setExtraHeaders({
      Authorization: `Bearer ${token}`
    })
  }

  /**
   * unsetAuthorization removes any previously set authorization credentials
   * (e.g. via setAuthorizationToken or via setExtraHeaders).
   * If there was no authorization set, it does nothing.
   */
  public unsetAuthorization() {
    delete this.extraHeaders['Authorization']
  }

  private convertGraphQLResponse(resp: GraphQLResponse, statusCode: number = 200): ClientResponse {
    // If there were no errors returned, the "errors" field should not be present on the response.
    // If no data is returned, according to the GraphQL spec,
    // the "data" field should only be included if no errors occurred during execution.
    if (resp.errors && resp.errors.length) {
      return {
        error: new ResponseError({
          statusCode,
          code: resp.errors[0]?.code,
          message: resp.errors[0]?.message,
          errors: resp.errors
        })
      }
    }

    if (resp.data === undefined) {
      return {
        error: new ResponseError({
          code: 'ResponseError',
          statusCode,
          message: 'Server returned no data'
        })
      }
    }

    return {
      data: resp.data
    }
  }

  // Determines whether the body is unparseable, plain text, or json (and assumes an invalid input if json)
  private async handleClientResponseError(response: globalThis.Response): Promise<ResponseError> {
    // In some cases, the server does not return JSON to communicate errors.
    // TODO: We should align it to always return JSON and in a consistent format.

    if (response.status === 401) {
      return new AuthorizationError()
    }

    const text = await response.text()

    try {
      const json = JSON.parse(text)

      if (response.status === 400) {
        if ((json?.code as ClientOperationErrorCodes) === 'InputValidationError') {
          const validationResult: ValidationResponseJSON = json
          return new InputValidationError({
            errors: validationResult.errors,
            message: validationResult.message,
            statusCode: response.status
          })
        }
      }

      return new ResponseError({
        code: json.errors[0]?.code,
        statusCode: response.status,
        errors: json.errors,
        message: json.errors[0]?.message ?? 'Invalid response from server'
      })
    } catch (e: any) {
      return new ResponseError({
        cause: e,
        statusCode: response.status,
        message: text || 'Invalid response from server'
      })
    }
  }

  private async request(url: string, options?: { signal?: AbortSignal, query?: Query, body?: Body, method?: string, headers?: Headers }) {
    const { headers, method = 'GET', signal } = options ?? {}
    return new Promise((resolve, reject) => {
      this.options.requestImpl({
        url,
        header: {
          ...this.baseHeaders,
          ...this.extraHeaders,
          ...headers,
        },
        method,
        signal,
        timeout: this.options.requestTimeoutMs,
        data: method.toUpperCase() === 'GET' ? undefined : options?.body,
        success(resp) {
          if (resp.statusCode >= 200 && resp.statusCode < 300) {
            resolve(resp.data)
          } else {
            // resolve(resp.)
          }
        },
        fail(e) {
          // reject(e)
        }
      })
    })
  }

  /***
   * Query makes a GET request to the server.
   * The method only throws an error if the request fails to reach the server or
   * the server returns a non-200 status code. Application errors are returned as part of the response.
   */
  public async query<RequestOptions extends QueryRequestOptions, Data = any, Error = any>(
    options: RequestOptions
  ): Promise<ClientResponse<Data, Error>> {
    const params: Query = {}
    const variables = this.stringifyInput(options.input)
    if (variables) {
      params['wg_variables'] = variables
    }
    if (options.subscribeOnce) {
      params['wg_subscribe_once'] = ''
    }
    this.operationUrl(options.operationName)

    try {
      const resp = await this.request(this.operationUrl(options.operationName), {
        query: params,
        signal: options.abortSignal
      })
      return this.convertGraphQLResponse(resp)
    } catch (error) {
      return this.handleClientResponseError(error)
    }
  }

  private async getCSRFToken(): Promise<string> {
    // request a new CSRF token if we don't have one
    if (!this.csrfToken) {
      // un-tested
      const res = await this.request(`${this.options.baseURL}/auth/cookie/csrf`, {
        headers: {
          ...this.baseHeaders,
          Accept: 'text/plain'
        }
      })

      this.csrfToken = res as string

      if (!this.csrfToken) {
        throw new Error('Failed to get CSRF token. Please make sure you are authenticated.')
      }
    }
    return this.csrfToken
  }

  /***
   * Mutate makes a POST request to the server.
   * The method only throws an error if the request fails to reach the server or
   * the server returns a non-200 status code. Application errors are returned as part of the response.
   */
  public async mutate<RequestOptions extends MutationRequestOptions, Data = any, Error = any>(
    options: RequestOptions
  ): Promise<ClientResponse<Data, Error>> {
    const params: Query = {}
    const url = this.operationUrl(options.operationName)

    const headers: Headers = {}

    if (this.shouldIncludeCsrfToken(this.isAuthenticatedOperation(options.operationName))) {
      headers['X-CSRF-Token'] = await this.getCSRFToken()
    }

    const resp = await this.fetchJson(url, {
      method: this.options.forceMethod || 'POST',
      signal: options.abortSignal,
      body: this.stringifyInput(options.input),
      headers
    })

    return this.fetchResponseToClientResponse(resp)
  }

  private shouldIncludeCsrfToken(orCondition: boolean) {
    if (this.csrfEnabled) {
      if (orCondition) {
        return true
      }
      if (typeof this.userIsAuthenticated !== 'undefined') {
        return this.userIsAuthenticated
      }
      // If fetchUser has never been called and we're in a browser
      // assume we do need the CSRF token. This shouldn't be a problem
      // because the CSRF token generator is always available
      if (typeof window !== 'undefined') {
        // Browser
        return true
      }
      // Backend
      return false
    }
    return false
  }
}

export function buildLiveQuery(url) {
  return function (callback, data) {
    const searchPairs = Object.keys(data || {}).map(key => `${key}=${encodeURIComponent(data[key])}`)
    searchPairs.push('wg_live=true')
    const search = searchPairs.join('&')
    const header: Record<string, string> = {}
    if (authHeader) {
      header.Authorization = authHeader
    }
    const requestTask = requestFun({
      url: `${baseUrl}${url}?${search}`,
      method: 'GET',
      data: data,
      header,
      enableChunked: true
    })
    requestTask.onChunkReceived(res => {
      callback(utf8ArrayToStr(new Uint8Array(res.data)))
    })
  }
}

export function uploadFile(options) {
  const header = options.header || {}
  if (authHeader) {
    header.Authorization = authHeader
  }
  return new Promise((resolve, reject) => {
    uploadFileFun({
      ...options,
      header,
      success(res) {
        resolve(res)
      },
      fail(err) {
        reject(err)
      }
    })
  })
}
