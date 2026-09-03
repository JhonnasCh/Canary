require('dotenv').config();

const config = {
  provider: process.env.AI_PROVIDER || 'local',
  apiKey: process.env.AI_API_KEY || '',
  modelName: process.env.AI_MODEL_NAME || 'gemini-1.5-pro',
  customEndpoint: process.env.AI_CUSTOM_ENDPOINT || '',
  guardianSecret: process.env.GUARDIAN_SECRET_KEY || 'canary-guard-default-key'
};

function getAiConfig() {
  return {
    provider: config.provider,
    modelName: config.modelName,
    customEndpoint: config.customEndpoint,
    hasApiKey: Boolean(config.apiKey && config.apiKey.trim().length > 0)
  };
}

function updateAiConfig(newConfig) {
  if (newConfig.provider) config.provider = newConfig.provider;
  if (newConfig.apiKey !== undefined) config.apiKey = newConfig.apiKey;
  if (newConfig.modelName) config.modelName = newConfig.modelName;
  if (newConfig.customEndpoint !== undefined) config.customEndpoint = newConfig.customEndpoint;

  return getAiConfig();
}

function getActiveCredentials() {
  return { ...config };
}

module.exports = {
  config,
  getAiConfig,
  updateAiConfig,
  getActiveCredentials
};
