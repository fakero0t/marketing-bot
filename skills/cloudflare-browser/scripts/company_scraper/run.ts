#!/usr/bin/env tsx
/**
 * Company Sourcing Script
 * Searches TheirStack API for companies and syncs results to Airtable.
 *
 * Usage:
 *   npx tsx run.ts
 *   npx tsx run.ts --query "Large Engineering Teams"
 *   npx tsx run.ts --schedule daily
 *
 * Requires .env with:
 *   THEIRSTACK_API_KEY, AIRTABLE_ACCESS_TOKEN, AIRTABLE_BASE_ID
 */
import 'dotenv/config';
import { z } from 'zod';
import { readFile } from 'fs/promises';

// ============================================================
// Types
// ============================================================

interface TheirStackSearchRequest {
  page?: number;
  limit?: number;
  offset?: number;
  cursor?: string;
  order_by?: Array<{ field: string; desc?: boolean }>;
  company_name_or?: string[];
  company_id_or?: string[];
  company_domain_or?: string[];
  min_employee_count?: number;
  max_employee_count?: number;
  company_country_code_or?: string[];
  company_country_code_not?: string[];
  industry_id_or?: number[];
  industry_id_not?: number[];
  funding_stage_or?: string[];
  only_yc_companies?: boolean;
  company_technology_slug_or?: string[];
  company_technology_slug_and?: string[];
  company_technology_slug_not?: string[];
  expand_technology_slugs?: string[];
  job_filters?: {
    job_title_or?: string[];
    job_title_not?: string[];
    job_title_pattern_or?: string[];
    job_title_pattern_and?: string[];
    job_title_pattern_not?: string[];
    job_description_pattern_or?: string[];
    job_description_pattern_not?: string[];
    job_description_contains_or?: string[];
    job_description_contains_not?: string[];
    job_seniority_or?: string[];
    job_country_code_or?: string[];
    job_country_code_not?: string[];
    location_pattern_or?: string[];
    remote_or?: string[];
    posted_at_max_age_days?: number;
    department_or?: string[];
  };
  include_total_results?: boolean;
  blur_company_data?: boolean;
}

interface TheirStackCompany {
  id: string;
  name: string;
  domain: string;
  linkedin_url?: string;
  employee_count?: number;
  employee_count_range?: string;
  industry?: string;
  industry_id?: number;
  country?: string;
  country_code?: string;
  city?: string;
  postal_code?: string;
  logo?: string;
  num_jobs?: number;
  num_jobs_last_30_days?: number;
  num_jobs_found?: number;
  founded_year?: number;
  annual_revenue_usd?: number;
  annual_revenue_usd_readable?: string;
  total_funding_usd?: number;
  funding_stage?: string;
  last_funding_round_date?: string;
  last_funding_round_amount_readable?: string;
  long_description?: string;
  seo_description?: string;
  yc_batch?: string;
  publicly_traded_symbol?: string;
  publicly_traded_exchange?: string;
  investors?: string[];
  company_keywords?: string[];
  technology_slugs?: string[];
  technology_names?: string[];
  technologies_found?: Array<{
    slug: string;
    name: string;
    category?: string;
    confidence?: string;
    job_count?: number;
    first_seen?: string;
    last_seen?: string;
  }>;
  jobs_found?: TheirStackJob[];
  has_blurred_data?: boolean;
}

interface TheirStackJob {
  id: string;
  title: string;
  department?: string;
  location?: string;
  remote?: string;
  experience_level?: string;
  posted_date?: string;
  description?: string;
  technologies?: string[];
}

interface TheirStackSearchResponse {
  metadata: {
    total_results?: number;
    total_companies?: number;
    truncated_results?: number;
    truncated_companies?: number;
  };
  data: TheirStackCompany[];
}

interface TheirStackErrorResponse {
  request_id: string | null;
  error: { code: string; title: string; description: string };
}

interface AirtableCompanyFields {
  'Company ID': string;
  'Company Name': string;
  'Website'?: string;
  'Company Size'?: string;
  'Employee Count'?: number;
  'Industry'?: string;
  'Industry ID'?: number;
  'Country'?: string;
  'Country Code'?: string;
  'City'?: string;
  'Logo URL'?: string;
  'LinkedIn URL'?: string;
  'Description'?: string;
  'Founded Year'?: number;
  'Total Jobs'?: number;
  'Jobs Last 30 Days'?: number;
  'Jobs Found'?: number;
  'Annual Revenue (USD)'?: number;
  'Total Funding (USD)'?: number;
  'Funding Stage'?: string;
  'Last Funding Date'?: string;
  'YC Batch'?: string;
  'Technology Slugs'?: string;
  'Technology Names'?: string;
  'Date Discovered': string;
  'Last Updated': string;
  'Status': string;
  'Notes'?: string;
}

interface AirtableJobFields {
  'Job ID': string;
  'Job Title': string;
  'Company': string[];
  'Department'?: string;
  'Job Type'?: string[];
  'Seniority Level'?: string;
  'Experience Years'?: number;
  'Employment Type'?: string;
  'Location'?: string;
  'Remote Policy'?: string;
  'Description'?: string;
  'Posted Date'?: string;
  'Date Discovered': string;
  'Status': string;
}

interface AirtableTechRequirementFields {
  'Job Posting': string[];
  'Technology Slug': string;
  'Technology Name'?: string;
  'Category'?: string;
  'Required/Preferred': string;
}

interface AirtableExecutionLogFields {
  'Query Name': string;
  'Execution Time': string;
  'Status': string;
  'Companies Found': number;
  'Companies Created': number;
  'Companies Updated': number;
  'Jobs Created': number;
  'Errors Count': number;
  'Errors'?: string;
  'Duration (seconds)': number;
  'Credits Used': number;
}

interface AirtableRecord<T> {
  id: string;
  fields: T;
  createdTime: string;
}

interface AirtableConfig {
  apiKey: string;
  baseId: string;
  tables: {
    companies: string;
    jobs: string;
    techRequirements: string;
    contacts: string;
    executionLog: string;
  };
}

interface QueryResult {
  query_name: string;
  companies_found: number;
  companies_created: number;
  companies_updated: number;
  jobs_created: number;
  tech_requirements_created: number;
  errors: string[];
  execution_time_seconds: number;
  timestamp: string;
  credits_used: number;
}

interface ExecutionSummary {
  total_queries: number;
  successful_queries: number;
  failed_queries: number;
  total_companies_processed: number;
  total_jobs_created: number;
  total_credits_used: number;
  total_execution_time_seconds: number;
  results: QueryResult[];
  errors: string[];
}

interface ValidationResult {
  isValid: boolean;
  errors: string[];
  warnings: string[];
  completenessScore: number;
}

interface DeduplicationResult {
  action: 'create' | 'update';
  existingRecordId?: string;
}

// ============================================================
// Config Schema (Zod)
// ============================================================

const QueryConfigSchema = z.object({
  name: z.string().min(1),
  enabled: z.boolean().default(true),
  schedule: z.enum(['daily', 'weekly', 'manual']).default('manual'),
  theirstack_request: z.object({
    page: z.number().optional(),
    limit: z.number().min(1).max(100).default(25),
    offset: z.number().optional(),
    cursor: z.string().optional(),
    order_by: z
      .array(z.object({ field: z.string(), desc: z.boolean().optional() }))
      .optional(),
    company_name_or: z.array(z.string()).optional(),
    company_id_or: z.array(z.string()).optional(),
    company_domain_or: z.array(z.string()).optional(),
    min_employee_count: z.number().optional(),
    max_employee_count: z.number().optional(),
    company_country_code_or: z.array(z.string()).optional(),
    company_country_code_not: z.array(z.string()).optional(),
    industry_id_or: z.array(z.number()).optional(),
    industry_id_not: z.array(z.number()).optional(),
    funding_stage_or: z.array(z.string()).optional(),
    only_yc_companies: z.boolean().optional(),
    company_technology_slug_or: z.array(z.string()).optional(),
    company_technology_slug_and: z.array(z.string()).optional(),
    company_technology_slug_not: z.array(z.string()).optional(),
    expand_technology_slugs: z.array(z.string()).optional(),
    job_filters: z
      .object({
        job_title_or: z.array(z.string()).optional(),
        job_title_not: z.array(z.string()).optional(),
        job_title_pattern_or: z.array(z.string()).optional(),
        job_title_pattern_and: z.array(z.string()).optional(),
        job_title_pattern_not: z.array(z.string()).optional(),
        job_description_pattern_or: z.array(z.string()).optional(),
        job_description_pattern_not: z.array(z.string()).optional(),
        job_description_contains_or: z.array(z.string()).optional(),
        job_description_contains_not: z.array(z.string()).optional(),
        job_seniority_or: z.array(z.string()).optional(),
        job_country_code_or: z.array(z.string()).optional(),
        job_country_code_not: z.array(z.string()).optional(),
        location_pattern_or: z.array(z.string()).optional(),
        remote_or: z.array(z.string()).optional(),
        posted_at_max_age_days: z.number().optional(),
        department_or: z.array(z.string()).optional(),
      })
      .optional(),
    include_total_results: z.boolean().optional(),
    blur_company_data: z.boolean().optional(),
  }) as z.ZodType<TheirStackSearchRequest>,
});

const QueriesConfigSchema = z.object({
  queries: z.array(QueryConfigSchema),
});

type QueryConfig = z.infer<typeof QueryConfigSchema>;

interface SkillConfig {
  theirstack: { apiKey: string; baseUrl: string };
  airtable: AirtableConfig;
  queries: QueryConfig[];
}

// ============================================================
// Logger
// ============================================================

type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LOG_LEVELS: Record<LogLevel, number> = { debug: 0, info: 1, warn: 2, error: 3 };
const currentLogLevel: LogLevel = (process.env.LOG_LEVEL as LogLevel) || 'info';

function log(level: LogLevel, event: string, data?: Record<string, unknown>): void {
  if (LOG_LEVELS[level] < LOG_LEVELS[currentLogLevel]) return;
  const entry = { level, event, timestamp: new Date().toISOString(), ...data };
  const method = level === 'error' ? console.error : level === 'warn' ? console.warn : console.log;
  method(JSON.stringify(entry));
}

const logger = {
  debug: (event: string, data?: Record<string, unknown>) => log('debug', event, data),
  info: (event: string, data?: Record<string, unknown>) => log('info', event, data),
  warn: (event: string, data?: Record<string, unknown>) => log('warn', event, data),
  error: (event: string, data?: Record<string, unknown>) => log('error', event, data),
};

// ============================================================
// Retry
// ============================================================

interface RetryOptions {
  maxAttempts: number;
  delayMs: number;
  exponentialBackoff: boolean;
  maxDelayMs?: number;
  shouldRetry?: (error: unknown) => boolean;
}

async function retry<T>(fn: () => Promise<T>, options: Partial<RetryOptions> = {}): Promise<T> {
  const opts: RetryOptions = {
    maxAttempts: 3,
    delayMs: 1000,
    exponentialBackoff: true,
    maxDelayMs: 30000,
    ...options,
  };
  let lastError: unknown;

  for (let attempt = 1; attempt <= opts.maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      if (attempt === opts.maxAttempts) break;
      if (opts.shouldRetry && !opts.shouldRetry(error)) break;

      let delay = opts.delayMs;
      if (opts.exponentialBackoff) delay = opts.delayMs * Math.pow(2, attempt - 1);
      if (opts.maxDelayMs) delay = Math.min(delay, opts.maxDelayMs);
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }
  throw lastError;
}

// ============================================================
// Rate Limiter
// ============================================================

class RateLimiter {
  private tokens: number;
  private lastRefill: number;
  private readonly maxTokens: number;
  private readonly refillIntervalMs: number;

  constructor(maxRequests: number, intervalMs: number) {
    this.maxTokens = maxRequests;
    this.tokens = maxRequests;
    this.lastRefill = Date.now();
    this.refillIntervalMs = intervalMs;
  }

  async acquire(): Promise<void> {
    this.refill();
    if (this.tokens > 0) {
      this.tokens--;
      return;
    }
    const waitTime = this.refillIntervalMs - (Date.now() - this.lastRefill);
    if (waitTime > 0) await new Promise((resolve) => setTimeout(resolve, waitTime));
    this.refill();
    this.tokens--;
  }

  private refill(): void {
    const elapsed = Date.now() - this.lastRefill;
    if (elapsed >= this.refillIntervalMs) {
      this.tokens = this.maxTokens;
      this.lastRefill = Date.now();
    }
  }
}

// ============================================================
// TheirStack Client
// ============================================================

class TheirStackAPIError extends Error {
  constructor(
    message: string,
    public code: string,
    public statusCode: number,
    public response?: TheirStackErrorResponse
  ) {
    super(message);
    this.name = 'TheirStackAPIError';
  }
}

class TheirStackRateLimitError extends TheirStackAPIError {
  constructor(public retryAfter: number) {
    super('Rate limit exceeded', 'RATE_LIMIT', 429);
    this.name = 'TheirStackRateLimitError';
  }
}

interface SearchResult {
  companies: TheirStackCompany[];
  creditsUsed: number;
  metadata?: TheirStackSearchResponse['metadata'];
}

class TheirStackClient {
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly timeout: number;
  private readonly maxRetries: number;

  constructor(config: { apiKey: string; baseUrl?: string; timeout?: number; maxRetries?: number }) {
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl || 'https://api.theirstack.com/v1';
    this.timeout = config.timeout || 60000;
    this.maxRetries = config.maxRetries || 3;
  }

  async searchCompanies(request: TheirStackSearchRequest): Promise<SearchResult> {
    logger.info('theirstack_search_started', {
      limit: request.limit,
      filters: this.summarizeFilters(request),
    });

    const response = await this.makeRequest(request);
    const creditsUsed = response.data.length * 3;

    logger.info('theirstack_search_completed', {
      companiesFound: response.data.length,
      creditsUsed,
      totalResults: response.metadata?.total_companies,
    });

    return { companies: response.data, creditsUsed, metadata: response.metadata };
  }

  async searchAllPages(request: TheirStackSearchRequest, maxPages = 10): Promise<SearchResult> {
    const allCompanies: TheirStackCompany[] = [];
    let currentPage = request.page || 0;
    const limit = request.limit || 25;
    let metadata: TheirStackSearchResponse['metadata'] | undefined;

    while (currentPage < (request.page || 0) + maxPages) {
      const response = await this.makeRequest({ ...request, page: currentPage, limit });
      metadata = response.metadata;
      allCompanies.push(...response.data);
      logger.debug('theirstack_page_fetched', { page: currentPage, count: response.data.length, total: allCompanies.length });
      if (response.data.length < limit) break;
      currentPage++;
    }

    return { companies: allCompanies, creditsUsed: allCompanies.length * 3, metadata };
  }

  private async makeRequest(request: TheirStackSearchRequest): Promise<TheirStackSearchResponse> {
    const url = `${this.baseUrl}/companies/search`;

    return retry(
      async () => {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);
        try {
          const response = await fetch(url, {
            method: 'POST',
            headers: { Authorization: `Bearer ${this.apiKey}`, 'Content-Type': 'application/json' },
            body: JSON.stringify(request),
            signal: controller.signal,
          });
          clearTimeout(timeoutId);

          if (response.status === 429) {
            const retryAfter = parseInt(response.headers.get('Retry-After') || '60', 10);
            throw new TheirStackRateLimitError(retryAfter);
          }
          if (response.status === 401) throw new TheirStackAPIError('Invalid API key', 'UNAUTHORIZED', 401);
          if (response.status === 402) throw new TheirStackAPIError('Insufficient credits', 'PAYMENT_REQUIRED', 402);

          if (!response.ok) {
            let errorData: TheirStackErrorResponse | undefined;
            try { errorData = (await response.json()) as TheirStackErrorResponse; } catch {}
            throw new TheirStackAPIError(
              errorData?.error?.description || `HTTP ${response.status}`,
              errorData?.error?.code || 'UNKNOWN',
              response.status,
              errorData
            );
          }
          return (await response.json()) as TheirStackSearchResponse;
        } catch (error) {
          clearTimeout(timeoutId);
          if (error instanceof TheirStackAPIError) throw error;
          if (error instanceof Error && error.name === 'AbortError') throw new TheirStackAPIError('Request timeout', 'TIMEOUT', 0);
          throw error;
        }
      },
      {
        maxAttempts: this.maxRetries,
        delayMs: 1000,
        exponentialBackoff: true,
        maxDelayMs: 30000,
        shouldRetry: (error) => {
          if (error instanceof TheirStackRateLimitError) return true;
          if (error instanceof TheirStackAPIError) {
            if (error.statusCode === 401 || error.statusCode === 402) return false;
            return error.statusCode >= 500;
          }
          return true;
        },
      }
    );
  }

  private summarizeFilters(request: TheirStackSearchRequest): Record<string, unknown> {
    const summary: Record<string, unknown> = {};
    if (request.min_employee_count) summary.minEmployees = request.min_employee_count;
    if (request.max_employee_count) summary.maxEmployees = request.max_employee_count;
    if (request.company_country_code_or) summary.countries = request.company_country_code_or;
    if (request.company_technology_slug_or) summary.technologies = request.company_technology_slug_or;
    if (request.job_filters?.job_title_pattern_or) summary.jobTitles = request.job_filters.job_title_pattern_or;
    return summary;
  }
}

// ============================================================
// Airtable Client
// ============================================================

class AirtableError extends Error {
  constructor(message: string, public statusCode?: number) {
    super(message);
    this.name = 'AirtableError';
  }
}

class AirtableClient {
  private readonly apiKey: string;
  private readonly baseId: string;
  private readonly tables: AirtableConfig['tables'];
  private readonly rateLimiter: RateLimiter;
  private readonly maxRetries: number;

  constructor(config: AirtableConfig, maxRetries = 3) {
    this.apiKey = config.apiKey;
    this.baseId = config.baseId;
    this.tables = config.tables;
    this.rateLimiter = new RateLimiter(5, 1000);
    this.maxRetries = maxRetries;
  }

  async findCompanyById(companyId: string): Promise<AirtableRecord<AirtableCompanyFields> | null> {
    const records = await this.listRecords<AirtableCompanyFields>(
      this.tables.companies,
      `{Company ID} = '${this.escapeFormula(companyId)}'`,
      1
    );
    return records[0] || null;
  }

  async findCompanyByDomain(domain: string): Promise<AirtableRecord<AirtableCompanyFields> | null> {
    const records = await this.listRecords<AirtableCompanyFields>(
      this.tables.companies,
      `LOWER({Website}) = '${this.escapeFormula(domain.toLowerCase())}'`,
      1
    );
    return records[0] || null;
  }

  async createCompany(fields: AirtableCompanyFields): Promise<string> {
    const record = await this.createRecord(this.tables.companies, fields);
    logger.info('company_created', { companyId: fields['Company ID'], recordId: record.id });
    return record.id;
  }

  async updateCompany(recordId: string, fields: Partial<AirtableCompanyFields>): Promise<void> {
    await this.updateRecord(this.tables.companies, recordId, fields);
    logger.info('company_updated', { recordId });
  }

  async findJobById(jobId: string): Promise<AirtableRecord<AirtableJobFields> | null> {
    const records = await this.listRecords<AirtableJobFields>(
      this.tables.jobs,
      `{Job ID} = '${this.escapeFormula(jobId)}'`,
      1
    );
    return records[0] || null;
  }

  async batchCreateJobs(jobs: AirtableJobFields[]): Promise<string[]> {
    return this.batchCreate(this.tables.jobs, jobs);
  }

  async batchCreateTechRequirements(requirements: AirtableTechRequirementFields[]): Promise<string[]> {
    return this.batchCreate(this.tables.techRequirements, requirements);
  }

  async logExecution(fields: AirtableExecutionLogFields): Promise<string> {
    const record = await this.createRecord(this.tables.executionLog, fields);
    logger.info('execution_logged', { queryName: fields['Query Name'], status: fields['Status'] });
    return record.id;
  }

  private async listRecords<T>(table: string, filterByFormula: string, maxRecords = 100): Promise<AirtableRecord<T>[]> {
    await this.rateLimiter.acquire();
    const params = new URLSearchParams({ filterByFormula, maxRecords: String(maxRecords) });
    const url = `https://api.airtable.com/v0/${this.baseId}/${encodeURIComponent(table)}?${params}`;
    const response = await this.fetchWithRetry(url, { method: 'GET' });
    const data = (await response.json()) as { records: Array<{ id: string; fields: T; createdTime: string }> };
    return data.records.map((r) => ({ id: r.id, fields: r.fields, createdTime: r.createdTime }));
  }

  private async createRecord<T>(table: string, fields: T): Promise<AirtableRecord<T>> {
    await this.rateLimiter.acquire();
    const url = `https://api.airtable.com/v0/${this.baseId}/${encodeURIComponent(table)}`;
    const response = await this.fetchWithRetry(url, { method: 'POST', body: JSON.stringify({ fields }) });
    const data = (await response.json()) as { id: string; fields: T; createdTime: string };
    return { id: data.id, fields: data.fields, createdTime: data.createdTime };
  }

  private async updateRecord<T>(table: string, recordId: string, fields: Partial<T>): Promise<void> {
    await this.rateLimiter.acquire();
    const url = `https://api.airtable.com/v0/${this.baseId}/${encodeURIComponent(table)}/${recordId}`;
    await this.fetchWithRetry(url, { method: 'PATCH', body: JSON.stringify({ fields }) });
  }

  private async batchCreate<T>(table: string, records: T[]): Promise<string[]> {
    const ids: string[] = [];
    const batchSize = 10;
    for (let i = 0; i < records.length; i += batchSize) {
      const batch = records.slice(i, i + batchSize);
      await this.rateLimiter.acquire();
      const url = `https://api.airtable.com/v0/${this.baseId}/${encodeURIComponent(table)}`;
      const response = await this.fetchWithRetry(url, {
        method: 'POST',
        body: JSON.stringify({ records: batch.map((fields) => ({ fields })) }),
      });
      const data = (await response.json()) as { records: Array<{ id: string; fields: T; createdTime: string }> };
      ids.push(...data.records.map((r) => r.id));
      logger.debug('batch_created', { table, batchCount: batch.length, totalCreated: ids.length });
    }
    return ids;
  }

  private async fetchWithRetry(url: string, init: { method: string; body?: string }): Promise<Response> {
    return retry(
      async () => {
        const response = await fetch(url, {
          ...init,
          headers: { Authorization: `Bearer ${this.apiKey}`, 'Content-Type': 'application/json' },
        });
        if (response.status === 429) throw new AirtableError('Rate limited', 429);
        if (response.status === 401) throw new AirtableError('Unauthorized - check API key', 401);
        if (response.status === 422) {
          const body = await response.text();
          throw new AirtableError(`Invalid data: ${body}`, 422);
        }
        if (!response.ok) {
          const body = await response.text();
          throw new AirtableError(`Airtable error ${response.status}: ${body}`, response.status);
        }
        return response;
      },
      {
        maxAttempts: this.maxRetries,
        delayMs: 1000,
        exponentialBackoff: true,
        shouldRetry: (error) => {
          if (error instanceof AirtableError) return error.statusCode === 429;
          return true;
        },
      }
    );
  }

  private escapeFormula(value: string): string {
    return value.replace(/'/g, "\\'");
  }
}

// ============================================================
// Normalizer
// ============================================================

const COUNTRY_CODE_MAP: Record<string, string> = {
  US: 'United States', GB: 'United Kingdom', CA: 'Canada', DE: 'Germany', FR: 'France',
  AU: 'Australia', IN: 'India', BR: 'Brazil', JP: 'Japan', CN: 'China', KR: 'South Korea',
  IL: 'Israel', NL: 'Netherlands', SE: 'Sweden', SG: 'Singapore', IE: 'Ireland', ES: 'Spain',
  IT: 'Italy', CH: 'Switzerland', AT: 'Austria', NZ: 'New Zealand', PL: 'Poland', PT: 'Portugal',
  DK: 'Denmark', NO: 'Norway', FI: 'Finland', BE: 'Belgium', MX: 'Mexico', AR: 'Argentina',
  CL: 'Chile', CO: 'Colombia',
};

const TECH_CATEGORY_MAP: Record<string, string> = {
  react: 'Frontend', vue: 'Frontend', angular: 'Frontend', svelte: 'Frontend', 'next-js': 'Frontend',
  typescript: 'Frontend', javascript: 'Frontend', 'node-js': 'Backend', python: 'Backend',
  ruby: 'Backend', go: 'Backend', java: 'Backend', 'c-sharp': 'Backend', rust: 'Backend', php: 'Backend',
  'react-native': 'Mobile', swift: 'Mobile', kotlin: 'Mobile', flutter: 'Mobile',
  postgresql: 'Data', mongodb: 'Data', redis: 'Data', elasticsearch: 'Data', mysql: 'Data', kafka: 'Data',
  tensorflow: 'AI/ML', pytorch: 'AI/ML', 'scikit-learn': 'AI/ML',
  aws: 'Infrastructure', gcp: 'Infrastructure', azure: 'Infrastructure',
  kubernetes: 'Infrastructure', docker: 'Infrastructure', terraform: 'Infrastructure',
};

const FUNDING_STAGE_MAP: Record<string, string> = {
  pre_seed: 'Pre-Seed', seed: 'Seed', series_a: 'Series A', series_b: 'Series B',
  series_c: 'Series C', series_d: 'Series D+', series_e: 'Series D+', series_f: 'Series D+',
  growth_equity_vc: 'Growth', private_equity: 'Private Equity',
  post_ipo_equity: 'Public', post_ipo_debt: 'Public',
};

function categorizeCompanySize(count?: number): string | undefined {
  if (!count) return undefined;
  if (count <= 10) return '1-10';
  if (count <= 50) return '11-50';
  if (count <= 200) return '51-200';
  if (count <= 500) return '201-500';
  if (count <= 1000) return '501-1000';
  if (count <= 5000) return '1001-5000';
  return '5000+';
}

function normalizeSeniorityLevel(level?: string): string | undefined {
  if (!level) return undefined;
  const map: Record<string, string> = {
    internship: 'Internship', entry: 'Entry Level', junior: 'Junior', mid: 'Mid Level',
    senior: 'Senior', staff: 'Staff', principal: 'Principal', lead: 'Lead',
    manager: 'Manager', director: 'Director', vp: 'VP', 'c-level': 'C-Level',
  };
  return map[level.toLowerCase()] || level;
}

function normalizeRemotePolicy(remote?: string): string | undefined {
  if (!remote) return undefined;
  const r = remote.toLowerCase();
  if (r === 'remote' || r === 'fully remote') return 'Remote';
  if (r === 'hybrid') return 'Hybrid';
  if (r === 'on-site' || r === 'onsite' || r === 'office') return 'On-site';
  return undefined;
}

function extractJobTypes(title?: string): string[] | undefined {
  if (!title) return undefined;
  const t = title.toLowerCase();
  const types: string[] = [];
  if (t.includes('full stack') || t.includes('fullstack')) types.push('Full Stack');
  if (t.includes('front') || t.includes('frontend')) types.push('Front End');
  if (t.includes('back') || t.includes('backend')) types.push('Back End');
  if (t.includes('mobile') || t.includes('ios') || t.includes('android')) types.push('Mobile');
  if (t.includes('devops') || t.includes('sre')) types.push('DevOps');
  if (t.includes('data engineer')) types.push('Data Engineering');
  if (t.includes('ml') || t.includes('machine learning') || t.includes('ai')) types.push('ML/AI');
  return types.length > 0 ? types : undefined;
}

function normalizeCompany(company: TheirStackCompany): AirtableCompanyFields {
  const now = new Date().toISOString();
  return {
    'Company ID': String(company.id),
    'Company Name': company.name,
    'Website': company.domain || undefined,
    'Company Size': categorizeCompanySize(company.employee_count),
    'Employee Count': company.employee_count,
    'Industry': company.industry,
    'Industry ID': company.industry_id,
    'Country': company.country || (company.country_code ? COUNTRY_CODE_MAP[company.country_code.toUpperCase()] || company.country_code : undefined),
    'Country Code': company.country_code,
    'City': company.city,
    'Logo URL': company.logo,
    'LinkedIn URL': company.linkedin_url,
    'Description': company.long_description,
    'Founded Year': company.founded_year,
    'Total Jobs': company.num_jobs,
    'Jobs Last 30 Days': company.num_jobs_last_30_days,
    'Jobs Found': company.num_jobs_found,
    'Annual Revenue (USD)': company.annual_revenue_usd,
    'Total Funding (USD)': company.total_funding_usd,
    'Funding Stage': company.funding_stage ? (FUNDING_STAGE_MAP[company.funding_stage.toLowerCase()] || 'Other') : undefined,
    'Last Funding Date': company.last_funding_round_date,
    'YC Batch': company.yc_batch,
    'Technology Slugs': company.technology_slugs?.join(', '),
    'Technology Names': company.technology_names?.join(', '),
    'Date Discovered': now.split('T')[0],
    'Last Updated': now,
    'Status': 'Active',
  };
}

function normalizeJob(job: TheirStackJob, companyRecordId: string): AirtableJobFields {
  const now = new Date().toISOString();
  return {
    'Job ID': String(job.id),
    'Job Title': job.title || 'Unknown',
    'Company': [companyRecordId],
    'Department': job.department,
    'Job Type': job.title ? extractJobTypes(job.title) : undefined,
    'Seniority Level': normalizeSeniorityLevel(job.experience_level),
    'Location': job.location,
    'Remote Policy': normalizeRemotePolicy(job.remote),
    'Description': job.description,
    'Posted Date': job.posted_date,
    'Date Discovered': now.split('T')[0],
    'Status': 'Open',
  };
}

function extractTechRequirements(job: TheirStackJob, jobRecordId: string): AirtableTechRequirementFields[] {
  if (!job.technologies || job.technologies.length === 0) return [];
  return job.technologies.map((tech) => ({
    'Job Posting': [jobRecordId],
    'Technology Slug': tech.toLowerCase(),
    'Technology Name': tech,
    'Category': TECH_CATEGORY_MAP[tech.toLowerCase()],
    'Required/Preferred': 'Required',
  }));
}

// ============================================================
// Validator
// ============================================================

const URL_REGEX = /^https?:\/\/.+\..+/;
const ISO_DATE_REGEX = /^\d{4}-\d{2}-\d{2}/;
const COUNTRY_CODE_REGEX = /^[A-Z]{2}$/;

function validateCompany(fields: AirtableCompanyFields): ValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  if (!fields['Company ID'] || fields['Company ID'].trim() === '') errors.push('Company ID is required');
  if (!fields['Company Name'] || fields['Company Name'].trim() === '') errors.push('Company Name is required');
  if (!fields['Website']) warnings.push('Website/domain is missing');
  if (!fields['Employee Count']) warnings.push('Employee count is missing');
  if (!fields['City']) warnings.push('City is missing');
  if (!fields['Country Code']) warnings.push('Country code is missing');
  if (fields['LinkedIn URL'] && !URL_REGEX.test(fields['LinkedIn URL'])) warnings.push('LinkedIn URL has invalid format');
  if (fields['Logo URL'] && !URL_REGEX.test(fields['Logo URL'])) warnings.push('Logo URL has invalid format');
  if (fields['Last Funding Date'] && !ISO_DATE_REGEX.test(fields['Last Funding Date'])) warnings.push('Last Funding Date has invalid format');
  if (fields['Employee Count'] !== undefined && fields['Employee Count'] < 0) errors.push('Employee count must be a positive number');
  if (fields['Country Code'] && !COUNTRY_CODE_REGEX.test(fields['Country Code'])) warnings.push('Country code is not valid ISO 2-letter code');

  const trackableFields: (keyof AirtableCompanyFields)[] = [
    'Company Name', 'Website', 'Employee Count', 'City', 'Country', 'Industry',
    'LinkedIn URL', 'Founded Year', 'Annual Revenue (USD)', 'Total Funding (USD)', 'Description', 'Technology Slugs',
  ];
  let populated = 0;
  for (const field of trackableFields) {
    const val = fields[field];
    if (val !== undefined && val !== null && val !== '') populated++;
  }

  return { isValid: errors.length === 0, errors, warnings, completenessScore: Math.round((populated / trackableFields.length) * 100) };
}

function validateJob(fields: AirtableJobFields): ValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];
  if (!fields['Job ID'] || fields['Job ID'].trim() === '') errors.push('Job ID is required');
  if (!fields['Job Title'] || fields['Job Title'].trim() === '') errors.push('Job Title is required');
  if (fields['Posted Date'] && !ISO_DATE_REGEX.test(fields['Posted Date'])) warnings.push('Posted Date has invalid format');
  if (!fields['Location']) warnings.push('Location is missing');
  if (!fields['Seniority Level']) warnings.push('Seniority Level is missing');
  return { isValid: errors.length === 0, errors, warnings, completenessScore: 0 };
}

// ============================================================
// Deduplication
// ============================================================

function normalizeDomain(input: string | null | undefined): string {
  if (!input || input.trim() === '') return '';
  let domain = input.trim().toLowerCase();
  domain = domain.replace(/^https?:\/\//, '');
  domain = domain.replace(/^www\./, '');
  domain = domain.replace(/\/+$/, '');
  return domain;
}

async function deduplicateCompany(fields: AirtableCompanyFields, airtable: AirtableClient): Promise<DeduplicationResult> {
  const byId = await airtable.findCompanyById(fields['Company ID']);
  if (byId) {
    logger.debug('company_dedup_found_by_id', { companyId: fields['Company ID'], recordId: byId.id });
    return { action: 'update', existingRecordId: byId.id };
  }
  if (fields['Website']) {
    const nd = normalizeDomain(fields['Website']);
    if (nd) {
      const byDomain = await airtable.findCompanyByDomain(nd);
      if (byDomain) {
        logger.debug('company_dedup_found_by_domain', { domain: nd, recordId: byDomain.id });
        return { action: 'update', existingRecordId: byDomain.id };
      }
    }
  }
  return { action: 'create' };
}

async function deduplicateJob(fields: AirtableJobFields, airtable: AirtableClient): Promise<DeduplicationResult> {
  const existing = await airtable.findJobById(fields['Job ID']);
  if (existing) return { action: 'update', existingRecordId: existing.id };
  return { action: 'create' };
}

// ============================================================
// Executor
// ============================================================

async function executeQuery(query: QueryConfig, theirstack: TheirStackClient, airtable: AirtableClient): Promise<QueryResult> {
  const startTime = Date.now();
  const result: QueryResult = {
    query_name: query.name, companies_found: 0, companies_created: 0, companies_updated: 0,
    jobs_created: 0, tech_requirements_created: 0, errors: [], execution_time_seconds: 0, timestamp: '', credits_used: 0,
  };

  logger.info('query_started', { query: query.name, timestamp: new Date().toISOString() });

  try {
    const searchResult = await theirstack.searchCompanies(query.theirstack_request);
    result.companies_found = searchResult.companies.length;
    result.credits_used = searchResult.creditsUsed;

    for (const rawCompany of searchResult.companies) {
      try {
        const companyFields = normalizeCompany(rawCompany);
        const validation = validateCompany(companyFields);
        if (!validation.isValid) {
          logger.warn('company_validation_failed', { company: companyFields['Company Name'], errors: validation.errors });
          result.errors.push(`Validation failed for ${companyFields['Company Name']}: ${validation.errors.join(', ')}`);
          continue;
        }

        const dedup = await deduplicateCompany(companyFields, airtable);
        let companyRecordId: string;
        if (dedup.action === 'update' && dedup.existingRecordId) {
          await airtable.updateCompany(dedup.existingRecordId, { ...companyFields, 'Last Updated': new Date().toISOString() });
          result.companies_updated++;
          companyRecordId = dedup.existingRecordId;
        } else {
          companyRecordId = await airtable.createCompany(companyFields);
          result.companies_created++;
        }

        if (rawCompany.jobs_found && rawCompany.jobs_found.length > 0) {
          const newJobs: AirtableJobFields[] = [];
          const newJobRawData: TheirStackJob[] = [];

          for (const rawJob of rawCompany.jobs_found) {
            const jobFields = normalizeJob(rawJob, companyRecordId);
            const jobValidation = validateJob(jobFields);
            if (!jobValidation.isValid) {
              logger.warn('job_validation_failed', { jobId: jobFields['Job ID'], errors: jobValidation.errors });
              continue;
            }
            const jobDedup = await deduplicateJob(jobFields, airtable);
            if (jobDedup.action === 'create') {
              newJobs.push(jobFields);
              newJobRawData.push(rawJob);
            }
          }

          if (newJobs.length > 0) {
            const jobRecordIds = await airtable.batchCreateJobs(newJobs);
            result.jobs_created += jobRecordIds.length;
            for (let i = 0; i < newJobRawData.length; i++) {
              const techReqs = extractTechRequirements(newJobRawData[i], jobRecordIds[i]);
              if (techReqs.length > 0) {
                await airtable.batchCreateTechRequirements(techReqs);
                result.tech_requirements_created += techReqs.length;
              }
            }
          }
        }

        logger.debug('company_processed', { company: companyFields['Company Name'], action: dedup.action });
      } catch (error) {
        const msg = error instanceof Error ? error.message : String(error);
        logger.error('company_processing_failed', { company: rawCompany.name, error: msg });
        result.errors.push(`Failed to process ${rawCompany.name}: ${msg}`);
      }
    }
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    logger.error('query_fetch_failed', { query: query.name, error: msg });
    result.errors.push(`Query failed: ${msg}`);
  }

  result.execution_time_seconds = (Date.now() - startTime) / 1000;
  result.timestamp = new Date().toISOString();

  try {
    const status = result.errors.length === 0 ? 'Success' : (result.companies_created > 0 || result.companies_updated > 0 ? 'Partial' : 'Failed');
    await airtable.logExecution({
      'Query Name': result.query_name, 'Execution Time': new Date().toISOString(), 'Status': status,
      'Companies Found': result.companies_found, 'Companies Created': result.companies_created,
      'Companies Updated': result.companies_updated, 'Jobs Created': result.jobs_created,
      'Errors Count': result.errors.length, 'Errors': result.errors.join('\n'),
      'Duration (seconds)': result.execution_time_seconds, 'Credits Used': result.credits_used,
    });
  } catch (error) {
    logger.error('execution_log_failed', { error: error instanceof Error ? error.message : String(error) });
  }

  logger.info('query_completed', {
    query: query.name, companiesFound: result.companies_found, companiesCreated: result.companies_created,
    companiesUpdated: result.companies_updated, jobsCreated: result.jobs_created,
    errors: result.errors.length, durationSeconds: result.execution_time_seconds,
  });

  return result;
}

async function executeAllQueries(queries: QueryConfig[], theirstack: TheirStackClient, airtable: AirtableClient): Promise<QueryResult[]> {
  const results: QueryResult[] = [];
  for (const query of queries) {
    try {
      results.push(await executeQuery(query, theirstack, airtable));
    } catch (error) {
      logger.error('query_execution_fatal', { query: query.name, error: error instanceof Error ? error.message : String(error) });
      results.push({
        query_name: query.name, companies_found: 0, companies_created: 0, companies_updated: 0,
        jobs_created: 0, tech_requirements_created: 0, errors: [error instanceof Error ? error.message : String(error)],
        execution_time_seconds: 0, timestamp: new Date().toISOString(), credits_used: 0,
      });
    }
  }
  return results;
}

// ============================================================
// Config Loader
// ============================================================

function getEnvOrThrow(key: string): string {
  const value = process.env[key];
  if (!value) throw new Error(`Missing required environment variable: ${key}`);
  return value;
}

async function loadConfig(queriesPath = './queries.json'): Promise<SkillConfig> {
  const raw = await readFile(queriesPath, 'utf-8');
  const queriesConfig = QueriesConfigSchema.parse(JSON.parse(raw));
  return {
    theirstack: {
      apiKey: getEnvOrThrow('THEIRSTACK_API_KEY'),
      baseUrl: process.env.THEIRSTACK_BASE_URL || 'https://api.theirstack.com/v1',
    },
    airtable: {
      apiKey: getEnvOrThrow('AIRTABLE_ACCESS_TOKEN'),
      baseId: getEnvOrThrow('AIRTABLE_BASE_ID'),
      tables: {
        companies: process.env.AIRTABLE_TABLE_COMPANIES || 'Companies',
        jobs: process.env.AIRTABLE_TABLE_JOBS || 'Job Postings',
        techRequirements: process.env.AIRTABLE_TABLE_TECHS || 'Technical Requirements',
        contacts: process.env.AIRTABLE_TABLE_CONTACTS || 'Contacts',
        executionLog: process.env.AIRTABLE_TABLE_EXECUTION_LOG || 'Execution Log',
      },
    },
    queries: queriesConfig.queries,
  };
}

// ============================================================
// Main Entry Point
// ============================================================

async function execute(config: SkillConfig): Promise<ExecutionSummary> {
  const startTime = Date.now();
  const enabledQueries = config.queries.filter((q) => q.enabled);

  logger.info('skill_execution_started', { totalQueries: config.queries.length, enabledQueries: enabledQueries.length });

  const theirstack = new TheirStackClient({ apiKey: config.theirstack.apiKey, baseUrl: config.theirstack.baseUrl });
  const airtable = new AirtableClient(config.airtable);
  const results = await executeAllQueries(enabledQueries, theirstack, airtable);
  const duration = (Date.now() - startTime) / 1000;

  const summary: ExecutionSummary = {
    total_queries: enabledQueries.length,
    successful_queries: results.filter((r) => r.errors.length === 0).length,
    failed_queries: results.filter((r) => r.errors.length > 0).length,
    total_companies_processed: results.reduce((sum, r) => sum + r.companies_found, 0),
    total_jobs_created: results.reduce((sum, r) => sum + r.jobs_created, 0),
    total_credits_used: results.reduce((sum, r) => sum + r.credits_used, 0),
    total_execution_time_seconds: duration,
    results,
    errors: results.flatMap((r) => r.errors),
  };

  logger.info('skill_execution_completed', {
    totalCompanies: summary.total_companies_processed, totalJobs: summary.total_jobs_created,
    totalCredits: summary.total_credits_used, duration: summary.total_execution_time_seconds,
  });

  return summary;
}

// ============================================================
// CLI
// ============================================================

function getArg(args: string[], flag: string): string | undefined {
  const idx = args.indexOf(flag);
  if (idx === -1 || idx + 1 >= args.length) return undefined;
  return args[idx + 1];
}

async function main() {
  const args = process.argv.slice(2);
  const queryName = getArg(args, '--query');
  const schedule = getArg(args, '--schedule') as 'daily' | 'weekly' | 'manual' | undefined;

  console.log('Loading config from ./queries.json...');
  const config = await loadConfig('./queries.json');

  if (queryName) {
    const query = config.queries.find((q) => q.name.toLowerCase().includes(queryName.toLowerCase()));
    if (!query) {
      console.error(`Query not found: "${queryName}"`);
      console.log('Available queries:');
      for (const q of config.queries) {
        console.log(`  - ${q.name} (${q.schedule}, ${q.enabled ? 'enabled' : 'disabled'})`);
      }
      process.exit(1);
    }
    config.queries = [{ ...query, enabled: true }];
  } else if (schedule) {
    const filtered = config.queries.filter((q) => q.enabled && q.schedule === schedule);
    if (filtered.length === 0) {
      console.log(`No enabled queries for schedule: ${schedule}`);
      process.exit(0);
    }
    config.queries = filtered;
  }

  console.log(`Running ${config.queries.filter((q) => q.enabled).length} query(ies)...\n`);

  const summary = await execute(config);

  console.log('\n========================================');
  console.log('         EXECUTION SUMMARY');
  console.log('========================================');
  console.log(`Queries:     ${summary.total_queries} (${summary.successful_queries} success, ${summary.failed_queries} failed)`);
  console.log(`Companies:   ${summary.total_companies_processed} found`);
  console.log(`Jobs:        ${summary.total_jobs_created} created`);
  console.log(`Credits:     ${summary.total_credits_used}`);
  console.log(`Duration:    ${summary.total_execution_time_seconds.toFixed(1)}s`);

  if (summary.errors.length > 0) {
    console.log(`\nErrors (${summary.errors.length}):`);
    for (const err of summary.errors) console.error(`  - ${err}`);
  }

  for (const result of summary.results) {
    console.log(`\n--- ${result.query_name} ---`);
    console.log(`  Found:   ${result.companies_found}`);
    console.log(`  Created: ${result.companies_created}`);
    console.log(`  Updated: ${result.companies_updated}`);
    console.log(`  Jobs:    ${result.jobs_created}`);
    console.log(`  Tech:    ${result.tech_requirements_created}`);
    console.log(`  Credits: ${result.credits_used}`);
    if (result.errors.length > 0) console.log(`  Errors:  ${result.errors.length}`);
  }
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
