// src/cti_platform/config/opensearch.config.ts
import { registerAs } from '@nestjs/config';
export default registerAs(' opensearch', () => ({
    opensearch: {
      node: process.env.OPENSEARCH_NODE || 'http://localhost:9200',  // URL of the OpenSearch node
      
    },
  }));
  
  