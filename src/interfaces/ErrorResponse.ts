import { HttpStatus } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';

export class CustomRpcException extends RpcException {
  constructor(
    statusCode: number = HttpStatus.BAD_REQUEST,
    message: string | string[] = 'An error occurred',
    error?: string,
    details?: any,
  ) {
    const errorObj = {
      statusCode,
      message,
      error: error || getErrorNameFromStatus(statusCode),
      timestamp: new Date().toISOString(),
      details,
    };

    super(errorObj);
  }
}

function getErrorNameFromStatus(statusCode: number): string {
  const statusMap: Record<number, string> = {
    400: 'Bad Request',
    401: 'Unauthorized',
    403: 'Forbidden',
    404: 'Not Found',
    409: 'Conflict',
    422: 'Unprocessable Entity',
    500: 'Internal Server Error',
    503: 'Service Unavailable',
  };

  return statusMap[statusCode] || 'Unknown Error';
}
