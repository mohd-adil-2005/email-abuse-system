/**
 * Email Abuse Detection System — JavaScript client
 * Use this in your app to call the middleware API (check signup, block temp emails, etc.)
 * @see https://github.com/mohd-adil-2005/email-abuse-system
 */

const axios = require('axios');

const DEFAULT_BASE_URL = 'http://localhost:8000';
const DEFAULT_TIMEOUT_MS = 10000;

/**
 * Build request config: base URL, timeout, and auth (Bearer token or X-API-Key).
 * @private
 */
function requestConfig(baseUrl, timeoutMs, token, apiKey) {
  const config = {
    baseURL: baseUrl || DEFAULT_BASE_URL,
    timeout: timeoutMs != null ? timeoutMs : DEFAULT_TIMEOUT_MS,
    headers: { 'Content-Type': 'application/json' },
  };
  if (token) config.headers['Authorization'] = `Bearer ${token}`;
  if (apiKey) config.headers['X-API-Key'] = apiKey;
  return config;
}

/**
 * Client for the Email Abuse Detection System API.
 * Use for signup validation (check_registration) and optional admin operations.
 */
class EmailAbuseClient {
  /**
   * @param {Object} [options]
   * @param {string} [options.baseUrl] - API base URL (default: http://localhost:8000)
   * @param {string} [options.apiKey] - Optional API key (X-API-Key header)
   * @param {string} [options.accessToken] - Optional JWT (Bearer) for protected endpoints
   * @param {number} [options.timeoutMs] - Request timeout in ms (default: 10000)
   */
  constructor(options = {}) {
    const baseUrl = options.baseUrl || DEFAULT_BASE_URL;
    const timeoutMs = options.timeoutMs != null ? options.timeoutMs : DEFAULT_TIMEOUT_MS;
    this._baseUrl = baseUrl.replace(/\/$/, '');
    this._timeoutMs = timeoutMs;
    this._apiKey = options.apiKey || null;
    this._accessToken = options.accessToken || null;
    this._client = axios.create(requestConfig(this._baseUrl, this._timeoutMs, this._accessToken, this._apiKey));
  }

  /**
   * Create a new client with the same options but a different Bearer token (e.g. after login).
   * @param {string} accessToken - JWT from POST /login
   * @returns {EmailAbuseClient}
   */
  withToken(accessToken) {
    return new EmailAbuseClient({
      baseUrl: this._baseUrl,
      timeoutMs: this._timeoutMs,
      apiKey: this._apiKey,
      accessToken: accessToken || this._accessToken,
    });
  }

  // ---------- Public (no auth) ----------

  /**
   * Health check.
   * @returns {Promise<{ status: string }>}
   */
  async health() {
    const { data } = await this._client.get('/health');
    return data;
  }

  /**
   * Check if a registration (email + phone) is allowed. Main middleware call for signup.
   * @param {{ email: string, phone: string }} data
   * @returns {Promise<{ allowed: boolean, email: string, phone_hash: string, status: string, is_temporary: boolean, spam_score: number, is_flagged: boolean, detection_notes?: string, message: string, registration_id?: number }>}
   */
  async checkRegistration(data) {
    const { data: res } = await this._client.post('/check_registration', {
      email: data.email,
      phone: data.phone,
    });
    return res;
  }

  /**
   * ML model info (training metadata). No auth required.
   * @returns {Promise<Object>}
   */
  async getModelInfo() {
    const { data } = await this._client.get('/model-info');
    return data;
  }

  // ---------- Auth ----------

  /**
   * Login with username and password. Returns JWT for use with withToken() or accessToken option.
   * @param {string} username
   * @param {string} password
   * @returns {Promise<{ access_token: string, token_type: string }>}
   */
  async login(username, password) {
    const { data } = await this._client.post('/login', { username, password });
    return data;
  }

  /**
   * Sign up a new user (optional).
   * @param {{ username: string, password: string, is_admin?: boolean }} data
   * @returns {Promise<{ access_token: string, token_type: string }>}
   */
  async signup(data) {
    const { data: res } = await this._client.post('/signup', {
      username: data.username,
      password: data.password,
      is_admin: data.is_admin === true,
    });
    return res;
  }

  // ---------- Protected (Bearer or X-API-Key) ----------

  /**
   * Get current user info.
   * @returns {Promise<{ id: number, username: string, is_admin: boolean, has_api_key: boolean, created_at: string }>}
   */
  async getMe() {
    const { data } = await this._client.get('/me');
    return data;
  }

  /**
   * Generate API key for current user (shown once).
   * @returns {Promise<{ api_key: string, message: string }>}
   */
  async generateApiKey() {
    const { data } = await this._client.post('/generate-api-key');
    return data;
  }

  /**
   * Get registration statistics.
   * @returns {Promise<{ total_registrations: number, blocked_registrations: number, unique_phones: number, temporary_blocked: number, flagged_registrations: number, avg_spam_score: number }>}
   */
  async getStats() {
    const { data } = await this._client.get('/stats');
    return data;
  }

  /**
   * List registrations with optional filters and pagination.
   * @param {{ page?: number, page_size?: number, phone_hash?: string, status?: string }} [params]
   * @returns {Promise<{ items: Array<Object>, total: number, page: number, page_size: number, total_pages: number }>}
   */
  async getRegistrations(params = {}) {
    const { data } = await this._client.get('/registrations', { params });
    return data;
  }

  /**
   * List flagged registrations.
   * @param {{ page?: number, page_size?: number }} [params]
   * @returns {Promise<{ items: Array<Object>, total: number, page: number, page_size: number, total_pages: number }>}
   */
  async getFlagged(params = {}) {
    const { data } = await this._client.get('/flagged', { params });
    return data;
  }

  /**
   * Get audit logs.
   * @param {{ page?: number, page_size?: number }} [params]
   * @returns {Promise<{ items: Array<Object>, total: number, page: number, page_size: number, total_pages: number }>}
   */
  async getAuditLogs(params = {}) {
    const { data } = await this._client.get('/audit_logs', { params });
    return data;
  }

  /**
   * Get phone registrations (phones with associated emails).
   * @param {{ page?: number, page_size?: number }} [params]
   * @returns {Promise<{ items: Array<Object>, total: number, page: number, page_size: number, total_pages: number }>}
   */
  async getPhoneRegistrations(params = {}) {
    const { data } = await this._client.get('/phone-registrations', { params });
    return data;
  }

  /**
   * Get blocked registrations.
   * @param {{ page?: number, page_size?: number }} [params]
   * @returns {Promise<{ items: Array<Object>, total: number, page: number, page_size: number, total_pages: number }>}
   */
  async getBlockedRegistrations(params = {}) {
    const { data } = await this._client.get('/blocked-registrations', { params });
    return data;
  }

  // ---------- Admin only (Bearer token with admin user) ----------

  /**
   * Override registration status (e.g. approve a blocked one).
   * @param {{ registration_id: number, status: 'approved'|'pending'|'blocked', reason: string }} data
   * @returns {Promise<{ success: boolean, registration: Object, message: string }>}
   */
  async override(data) {
    const { data: res } = await this._client.post('/override', {
      registration_id: data.registration_id,
      status: data.status,
      reason: data.reason,
    });
    return res;
  }

  /**
   * Manually update registration flags (spam, temporary, status, notes).
   * @param {{ registration_id: number, reason: string, is_temporary?: boolean, is_flagged?: boolean, spam_score?: number, status?: string, detection_notes?: string }} data
   * @returns {Promise<{ success: boolean, registration: Object, message: string }>}
   */
  async manualUpdate(data) {
    const { data: res } = await this._client.post('/manual-update', {
      registration_id: data.registration_id,
      reason: data.reason,
      is_temporary: data.is_temporary,
      is_flagged: data.is_flagged,
      spam_score: data.spam_score,
      status: data.status,
      detection_notes: data.detection_notes,
    });
    return res;
  }

  /**
   * Bulk block registrations by IDs.
   * @param {{ registration_ids: number[], reason: string }} data
   * @returns {Promise<{ success: boolean, blocked_count: number, message: string }>}
   */
  async bulkBlock(data) {
    const { data: res } = await this._client.post('/bulk_block', {
      registration_ids: data.registration_ids,
      reason: data.reason,
    });
    return res;
  }

  /**
   * Bulk import/check registrations (admin).
   * @param {{ registrations: Array<{ email: string, phone: string }>, skip_rate_limit?: boolean }} data
   * @returns {Promise<{ success: boolean, total: number, successful: number, failed: number, results: Array<Object>, processing_time_seconds: number }>}
   */
  async bulkImport(data) {
    const { data: res } = await this._client.post('/bulk_import', {
      registrations: data.registrations,
      skip_rate_limit: data.skip_rate_limit === true,
    });
    return res;
  }

  /**
   * Whitelist a phone number (allow despite suspicious pattern) and approve existing blocked regs.
   * @param {{ phone_hash: string, phone_normalized: string, reason: string }} data
   * @returns {Promise<{ success: boolean, phone_hash: string, phone_normalized: string, updated_registrations: number, message: string }>}
   */
  async phoneWhitelist(data) {
    const { data: res } = await this._client.post('/phone-whitelist', {
      phone_hash: data.phone_hash,
      phone_normalized: data.phone_normalized,
      reason: data.reason,
    });
    return res;
  }
}

module.exports = { EmailAbuseClient };
module.exports.EmailAbuseClient = EmailAbuseClient;
