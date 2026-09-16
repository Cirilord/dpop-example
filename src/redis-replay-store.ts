import type Redis from 'ioredis';

import type { ReplayStore } from './dpop/validate-jti';

export class RedisReplayStore implements ReplayStore {
  constructor(private readonly redis: Redis) {}

  async consumeOnce(jkt: string, jti: string, ttlSeconds: number): Promise<boolean> {
    const key = `dpop:jti:${jkt}:${jti}`;
    const result = await this.redis.set(key, '1', 'EX', ttlSeconds, 'NX');
    return result === 'OK';
  }
}
