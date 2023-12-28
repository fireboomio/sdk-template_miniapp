import {
  type ClientConfig,
  type QueryRequestOptions,
  type MutationRequestOptions,
  type SubscriptionRequestOptions,
  type SubscriptionEventHandler,
  type ClientResponse,
  type GraphQLResponse,
  type ClientOperationErrorCodes,
  type ValidationResponseJSON,
  type UploadRequestOptions,
  type UploadValidationOptions,
  type Headers,
  type PromiseOr,
  ResponseError,
  AuthorizationError,
  InputValidationError
} from "@fireboom/client";
import { utf8ArrayToStr } from './decoder'

type Query = Record<string, any>
type Body = Record<string, any>

export type UploadFile = {
  /** 本地临时文件路径 */
  path: string
  /** 本地临时文件大小，单位 B */
  size: number
  /** 文件的 MIME 类型
   * @supported h5
   */
  type?: string
}

export type MiniappUploadConfig<ProviderName = any, ProfileName = any, Meta = any> = Omit<UploadRequestOptions<ProviderName, ProfileName, Meta>, 'files' | 'abortSignal'> & { file: UploadFile }

export type MiniappRequestInterceptorArg = { url: string, method: string, headers: Headers, body?: Body }
export type MiniappResponse = { data: any, statusCode: number, header?: Headers, cookies?: string[], profile?: any, exception?: any }
export type MiniappInterceptors = {
  requestInterceptor?: (args: MiniappRequestInterceptorArg) => PromiseOr<MiniappRequestInterceptorArg> | null | undefined
  responseInterceptor?: (args: { request: MiniappRequestInterceptorArg, response: MiniappResponse }) => PromiseOr<MiniappResponse> | null | undefined
}
export type MiniappClientConfig = Omit<ClientConfig, 'customFetch' | 'requestInterceptor' | 'responseInterceptor'> & {
  requestImpl: (options: any) => void
  uploadImpl: (options: any) => void
  skipCSRF?: boolean
} & MiniappInterceptors

export type MiniappRequestConfig = {
  enableChunked?: boolean, signal?: AbortSignal, query?: Query, body?: Body, method?: string, headers?: Headers, timeout?: number
} & MiniappInterceptors

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

  protected addUrlParams(url: string, queryParams: Query): string {
    let q = ''
    // stable stringify
    Object.keys(queryParams).sort().forEach(key => {
      if (q) {
        q += '&'
      }
      q += `${key}=${encodeURIComponent(queryParams[key])}`
    })
    q = q.replace('=&', '&')
    if (q.endsWith('=')) {
      q = q.slice(0, -1)
    }
    return url + (q ? `?${q}` : '')
  }

  protected searchParams(queryParams?: Query) {
    const q = { ...queryParams }
    if (this.options.applicationHash) {
      q['wg_api_hash'] = this.options.applicationHash
    }

    return q
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
  private handleClientResponseError(response: string | {
    data: any
    statusCode: number
  }): ResponseError {
    if (typeof response === 'string') {
      return new ResponseError({
        statusCode: 999,
        message: response
      })
    }
    if (typeof response.data === 'string') {
      return new ResponseError({
        statusCode: response.statusCode,
        message: (response.data as string).replace(/hooks pipeline failed:/g, '').trim()
      })
    }
    if (response.statusCode === 401) {
      return new AuthorizationError()
    }

    if (response.statusCode === 400) {
      if ((response.data?.code as ClientOperationErrorCodes) === 'InputValidationError') {
        const validationResult: ValidationResponseJSON = response.data
        return new InputValidationError({
          errors: validationResult.errors,
          message: validationResult.message,
          statusCode: response.statusCode
        })
      }
    }
    if (response.data.errors) {
      return new ResponseError({
        code: response.data.errors[0]?.code,
        statusCode: response.statusCode,
        errors: response.data.errors,
        message: response.data.errors[0]?.message ?? 'Invalid response from server'
      })
    }
    try {
      return new ResponseError({
        statusCode: response.statusCode,
        message: ('error' in response.data ? response.data.error : response.data).replaceAll('hooks pipeline failed:', '').trim() || 'Invalid response from server'
      })
    } catch (error) {
      return new ResponseError({
        statusCode: response.statusCode,
        message: 'Invalid response from server'
      })
    }
  }

  private async fetchResponseToClientResponse(req: Promise<any>) {
    try {
      const response = await req
      return this.convertGraphQLResponse(response)
    } catch (error) {
      return { error: this.handleClientResponseError(error) }
    }
  }

  private async request(url: string, options?: MiniappRequestConfig) {
    const { headers, method, signal, enableChunked, timeout } = options ?? {}
    let _url = options?.query ? this.addUrlParams(url, options.query) : url
    let _headers: Headers = {
      ...this.baseHeaders,
      ...this.extraHeaders,
      ...headers,
    }
    let _method = method?.toUpperCase() ?? 'GET'
    let _body = _method === 'GET' ? undefined : options?.body
    
    /**
     * run global request interceptor before fetch
     * and use the returned value needed
     */
    if (this.options.requestInterceptor) {
      const res = await this.options.requestInterceptor({ url: _url, headers: _headers, method: _method, body: _body })
      if (res) {
        _url = res.url
        _headers = res.headers
        _method = res.method
        _body = res.body
      }
    }
    /**
       * run request interceptor before global interceptor
       * and use the returned value needed
       */
    if (options?.requestInterceptor) {
      const res = await options.requestInterceptor({ url: _url, headers: _headers, method: _method, body: _body })
      if (res) {
        _url = res.url
        _headers = res.headers
        _method = res.method
        _body = res.body
      }
    }
    const request = { url: _url, headers: _headers, method: _method, body: _body }
    let requestTask
    const promise = new Promise<MiniappResponse>((resolve, reject) => {
      requestTask = this.options.requestImpl({
        url: _url,
        header: _headers,
        method: _method,
        signal,
        timeout: timeout ?? this.options.requestTimeoutMs,
        enableChunked,
        data: _body,
        responseType: 'text',
        dataType: '',
        async success(response) {
          let _resp = response
          try {
            _resp.data = JSON.parse(_resp.data)
          } catch (error) {
            //
          }
          /**
           * run global interceptor after fetch
           * and use the returned value as needed
           */
          if (this.options.responseInterceptor) {
            const resp = await this.options.responseInterceptor({ request, response })
            if (resp) {
              _resp = resp
            }
          }
          /**
           * run request interceptor after global interceptor
           * and use the returned value as needed
           */
          if (options?.responseInterceptor) {
            const resp = await options.responseInterceptor({ request, response })
            if (resp) {
              _resp = resp
            }
          }
          if (_resp.statusCode >= 200 && _resp.statusCode < 300) {
            resolve(_resp.data)
          } else {
            reject(_resp)
          }
        },
        fail(e) {
          reject(e.errMsg)
        }
      })
    })
    return [promise, requestTask]
  }

  /***
   * Query makes a GET request to the server.
   * The method only throws an error if the request fails to reach the server or
   * the server returns a non-200 status code. Application errors are returned as part of the response.
   */
  public async query<RequestOptions extends Omit<QueryRequestOptions, 'requestInterceptor' | 'responseInterceptor'> & MiniappInterceptors, Data = any, Error = any>(
    options: RequestOptions
  ): Promise<ClientResponse<Data, Error>> {
    const params: Query = this.searchParams()
    const variables = this.stringifyInput(options.input)
    if (variables) {
      params['wg_variables'] = variables
    }
    if (options.subscribeOnce) {
      params['wg_subscribe_once'] = ''
    }
    this.operationUrl(options.operationName)

    const resp = await (this.request(this.operationUrl(options.operationName), {
      method: this.options.forceMethod || 'GET',
      query: params,
      signal: options.abortSignal,
      headers: options.headers,
      timeout: options.timeout,
      requestInterceptor: options.requestInterceptor,
      responseInterceptor: options.responseInterceptor
    }))
    return this.fetchResponseToClientResponse(resp[0])
  }

  private async getCSRFToken(): Promise<string> {
    // request a new CSRF token if we don't have one
    if (!this.csrfToken) {
      // un-tested
      const res = await (await this.request(`${this.options.baseURL}/auth/cookie/csrf`, {
        headers: {
          ...this.baseHeaders,
          Accept: 'text/plain'
        }
      })[0])

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
  public async mutate<RequestOptions extends Omit<MutationRequestOptions, 'requestInterceptor' | 'responseInterceptor'> & MiniappInterceptors, Data = any, Error = any>(
    options: RequestOptions
  ): Promise<ClientResponse<Data, Error>> {
    const url = this.operationUrl(options.operationName)

    const headers: Headers = { ...options.headers }

    if (this.shouldIncludeCsrfToken(this.isAuthenticatedOperation(options.operationName))) {
      headers['X-CSRF-Token'] = await this.getCSRFToken()
    }

    const resp = await this.request(url, {
      method: this.options.forceMethod || 'POST',
      query: this.searchParams(),
      body: options.input,
      headers,
      signal: options.abortSignal,
      timeout: options.timeout,
      requestInterceptor: options.requestInterceptor,
      responseInterceptor: options.responseInterceptor
    })
    return this.fetchResponseToClientResponse(resp[0])
  }

  private shouldIncludeCsrfToken(orCondition: boolean) {
    if (!this.options.skipCSRF && this.csrfEnabled) {
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

  /**
   * Set up subscriptions over SSE
   */
  public async subscribe<
    RequestOptions extends Omit<SubscriptionRequestOptions, 'requestInterceptor' | 'responseInterceptor'> & MiniappInterceptors,
    Data = any,
    Error = any,
  >(options: RequestOptions, cb?: SubscriptionEventHandler<Data, Error>) {
    if (options.subscribeOnce) {
      const result = await this.query<RequestOptions, Data, Error>(options)
      return result
    }
    const params: Query = this.searchParams({ wg_sse: '' })
    const variables = this.stringifyInput(options.input)
    if (variables) {
      params['wg_variables'] = variables
    }
    if (options.liveQuery) {
      params['wg_live'] = ''
    }

    const url = this.operationUrl(options.operationName)
    const [_, requestTask] = await (await this.request(url, {
      query: params,
      method: this.options.forceMethod || 'GET',
      signal: options.abortSignal,
      enableChunked: true,
      headers: options.headers,
      timeout: options.timeout,
      requestInterceptor: options.requestInterceptor,
      responseInterceptor: options.responseInterceptor
    }))
    requestTask.onChunkReceived(res => {
      const chunk = utf8ArrayToStr(new Uint8Array(res.data))
      const parts = chunk.split('\n\n')
      for (const part of parts) {
        const content = part.substring(6).trim()
        if (content) {
          const data = JSON.parse(content)
          cb?.(this.convertGraphQLResponse(data))
        }
      }
    })
  }

  /**
   * Upload one file
   */
  public async uploadFile<UploadOptions extends MiniappUploadConfig>(
    config: UploadOptions,
    validation?: UploadValidationOptions
  ): Promise<string> {
    this.validateFile(config, validation)

    const headers: Headers = {}

    if (this.shouldIncludeCsrfToken(validation?.requireAuthentication ?? true)) {
      headers['X-CSRF-Token'] = await this.getCSRFToken()
    }

    const params: Query = this.searchParams()

    // append directory
    if (config.directory) {
      params['directory'] = config.directory
    }

    if ('profile' in config) {
      headers['X-Upload-Profile'] = (config as any).profile
    }

    if ('meta' in config) {
      headers['X-Metadata'] = (config as any).meta ? JSON.stringify((config as any).meta) : ''
    }
    return new Promise((resolve, reject) => {
      this.options.uploadImpl({
        filePath: config.file.path,
        name: config.file.path.split('/').pop(),
        url: `${this.options.baseURL}/s3/${config.provider}/upload`,
        success(res) {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve((res.data as { key: string }[]).map(i => i.key)[0])
          } else {
            reject(res.data)
          }
        },
        fail(res) {
          reject(res.errMsg)
        }
      })
    })
  }

  public validateFile(config: MiniappUploadConfig, validation?: UploadValidationOptions) {
    const file = config.file
    if (
      validation?.maxAllowedUploadSizeBytes &&
      file.size > validation.maxAllowedUploadSizeBytes
    ) {
      throw new Error(
        `file ${file.path} with size ${file.size} exceeds the maximum allowed (${validation.maxAllowedUploadSizeBytes})`
      )
    }
    if (validation?.allowedFileExtensions && file.path.includes('.')) {
      const ext = file.path.substring(file.path.indexOf('.') + 1).toLowerCase()
      if (ext) {
        if (validation.allowedFileExtensions.findIndex(item => item.toLocaleLowerCase()) < 0) {
          throw new Error(`file ${file.path} with extension ${ext} is not allowed`)
        }
      }
    }
    if (validation?.allowedMimeTypes && file.type) {
      const mimeType = file.type
      const idx = validation.allowedMimeTypes.findIndex(item => {
        // Full match
        if (item == mimeType) {
          return true
        }
        // Try wildcard match. This is a bit brittle but it should be fine
        // as long as profile?.allowedMimeTypes contains only valid entries
        return mimeType.match(new RegExp(item.replace('*', '.*')))
      })
      if (idx < 0) {
        throw new Error(`file ${file.path} with MIME type ${mimeType} is not allowed`)
      }
    }

  }
}
