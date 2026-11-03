// Hostinger Business Plan Node.js PM2 Process Configuration
module.exports = {
  apps: [
    {
      name: "it-hardware-platform",
      script: "./dist/server.cjs",
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: "512M",
      env: {
        NODE_ENV: "production",
        PORT: 3000
      }
    }
  ]
};
