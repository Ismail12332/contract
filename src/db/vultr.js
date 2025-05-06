const AWS = require('aws-sdk');

// Настройки Vultr Object Storage
const VULTR_ACCESS_KEY = process.env.VULTR_ACCESS_KEY;
const VULTR_SECRET_KEY = process.env.VULTR_SECRET_KEY;
const VULTR_ENDPOINT_URL = process.env.VULTR_ENDPOINT_URL;
const BUCKET_NAME = process.env.VULTR_BUCKET_NAME;

// Создание клиента S3 для Vultr
const s3 = new AWS.S3({
    endpoint: VULTR_ENDPOINT_URL,
    accessKeyId: VULTR_ACCESS_KEY,
    secretAccessKey: VULTR_SECRET_KEY,
    s3ForcePathStyle: true, // Убедитесь, что используется правильный стиль пути
});

module.exports = {
    s3,
    BUCKET_NAME,
};