import { describe, expect, it } from 'vitest';
import { PointsService, type PointEvent } from './points.js';

const event = (over: Partial<PointEvent> = {}): PointEvent => ({
  userId: 'u1',
  kind: 'lesson_completed',
  at: new Date('2026-01-01T00:00:00Z'),
  ...over,
});

describe('PointsService', () => {
  it('awards 10 points for completing a lesson', () => {
    const svc = new PointsService();
    svc.award(event());
    expect(svc.totalFor('u1')).toBe(10);
  });

  it('awards 25 points for passing a quiz', () => {
    const svc = new PointsService();
    svc.award(event({ kind: 'quiz_passed' }));
    expect(svc.totalFor('u1')).toBe(25);
  });

  it('keeps each user’s points separate', () => {
    const svc = new PointsService();
    svc.award(event({ userId: 'u1' }));
    svc.award(event({ userId: 'u2', kind: 'quiz_passed' }));
    expect(svc.totalFor('u1')).toBe(10);
    expect(svc.totalFor('u2')).toBe(25);
  });

  it('starts a user with no events at level 1', () => {
    const svc = new PointsService();
    const level = svc.levelFor('nobody');
    expect(level.number).toBe(1);
    expect(level.title).toBe('Novice');
    expect(level.pointsToNext).toBe(100);
  });

  it('promotes to level 2 exactly at the 100 point threshold', () => {
    const svc = new PointsService();
    for (let i = 0; i < 4; i += 1) svc.award(event({ kind: 'quiz_passed' }));
    expect(svc.totalFor('u1')).toBe(100);
    expect(svc.levelFor('u1').number).toBe(2);
    expect(svc.levelFor('u1').pointsIntoLevel).toBe(0);
  });

  it('reports null pointsToNext at the maximum level', () => {
    const svc = new PointsService();
    for (let i = 0; i < 40; i += 1) svc.award(event({ kind: 'quiz_passed' }));
    const level = svc.levelFor('u1');
    expect(level.number).toBe(LEVEL_COUNT);
    expect(level.pointsToNext).toBeNull();
  });
});

const LEVEL_COUNT = 5;
