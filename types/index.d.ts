declare module '@tonsolutions/telemetree-node' {
  export interface TelegramUser {
    id: number;
    username?: string;
    first_name?: string;
    last_name?: string;
    is_premium?: boolean;
    language_code?: string;
  }

  export interface TelegramChat {
    id: number;
    type: 'private' | 'group' | 'supergroup' | 'channel';
  }

  export interface TelegramMessage {
    message_id: number;
    from?: TelegramUser;
    chat: TelegramChat;
    date: number;
    text?: string;
    edit_date?: number;
  }

  export interface TelegramInlineQuery {
    id: string;
    from: TelegramUser;
    query: string;
    offset: string;
  }

  export interface TelegramUpdate {
    message?: TelegramMessage;
    edited_message?: TelegramMessage;
    inline_query?: TelegramInlineQuery;
  }

  export interface EventProperties {
    [key: string]: any;
  }

  export interface TrackingPayload {
    application_id: string;
    datetime: string;
    username?: string;
    firstname?: string;
    lastname?: string;
    is_premium: boolean;
    telegram_id: number;
    language?: string;
    session_id: number;
    event_source: string;
    event_type: string;
    app_name: string;
    message_id?: number;
    chat_id?: number;
    chat_type?: string;
    text?: string;
    date?: number;
    event_properties: EventProperties;
  }

  export interface EncryptedEventData {
    body: string;
    key: string;
    iv: string;
  }

  export interface TrackingResponse {
    success: boolean;
    error?: string;
  }

  export interface BotTrackingConfigData {
    host: string;
    auto_capture_telegram_events: string[];
    auto_capture_commands: string[];
    app_name?: string;
    publicKey?: string;
  }

  export class BotTrackingConfig {
    constructor(data: BotTrackingConfigData);
    validate(data: BotTrackingConfigData): void;
  }

  export interface EncryptedEventData {
    encrypted_message: string;
    encrypted_key: string;
    encrypted_iv: string;
  }

  export class EncryptedEvent {
    constructor(data: EncryptedEventData);
    validate(data: EncryptedEventData): void;
  }

  export class Config {
    constructor(projectId: string, apiKey: string);
    initialize(): Promise<void>;
    config: BotTrackingConfig;
  }

  export class EncryptionService {
    constructor(publicKey: string);
    encrypt(data: any): Promise<EncryptedEventData>;
  }

  export class EventBuilder {
    constructor(settings: Config);
    buildPayload(user: TelegramUser, eventType?: string, eventData?: EventProperties): TrackingPayload;
    buildPayloadUpdate(update: TelegramUpdate, eventType?: string, eventData?: EventProperties): TrackingPayload;
    parseTelegramUpdate(updateDict: any): TelegramUpdate | null;
    shouldTrackUpdate(update: TelegramUpdate): boolean;
  }

  export class HttpClient {
    constructor(settings: Config);
    post(payload: EncryptedEventData): Promise<TrackingResponse>;
  }

  export class TelemetreeClient {
    constructor(projectId: string, apiKey: string);
    initialize(): Promise<void>;
    track(user: TelegramUser, eventName: string, eventProperties?: EventProperties): Promise<TrackingResponse>;
    trackUpdate(updateData: TelegramUpdate): Promise<TrackingResponse | void>;
  }
}
