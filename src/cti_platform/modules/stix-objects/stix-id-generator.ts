const NAMESPACE = '6ba7b810-9dad-11d1-80b4-00c04fd430c8';
import { v5 as uuidv5 } from 'uuid';
export const generateStixId = (type: string, value: any): string => {
  return `${type}--${uuidv5(value, NAMESPACE)}`;
};