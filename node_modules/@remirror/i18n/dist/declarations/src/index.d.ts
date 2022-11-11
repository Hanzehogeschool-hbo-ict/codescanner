import { i18n } from '@lingui/core';
export type { AllLocaleData, AllMessages, I18n, Locale, LocaleData, Locales, MessageDescriptor, Messages, } from '@lingui/core';
export { formats, setupI18n } from '@lingui/core';
export { i18n };
/**
 * Detect the locale that is being
 */
export declare function detectLocale(key?: string, fallback?: string): string;
