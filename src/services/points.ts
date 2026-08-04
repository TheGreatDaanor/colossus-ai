/**
 * Points and levels.
 *
 * A deep module: small public surface (award, totalFor, levelFor), with the
 * rules living inside. Callers cannot reach past this interface, which is what
 * makes a single test boundary around it meaningful.
 */

export type PointEvent = {
  readonly userId: string;
  readonly kind: 'lesson_completed' | 'quiz_passed';
  readonly at: Date;
};

export type Level = {
  readonly number: number;
  readonly title: string;
  readonly pointsIntoLevel: number;
  readonly pointsToNext: number | null;
};

const POINTS_BY_KIND: Record<PointEvent['kind'], number> = {
  lesson_completed: 10,
  quiz_passed: 25,
};

const LEVEL_THRESHOLDS = [0, 100, 300, 600, 1000] as const;
const LEVEL_TITLES = ['Novice', 'Apprentice', 'Practitioner', 'Expert', 'Master'] as const;

export class PointsService {
  readonly #events: PointEvent[] = [];

  award(event: PointEvent): void {
    this.#events.push(event);
  }

  totalFor(userId: string): number {
    return this.#events
      .filter((e) => e.userId === userId)
      .reduce((sum, e) => sum + POINTS_BY_KIND[e.kind], 0);
  }

  levelFor(userId: string): Level {
    const total = this.totalFor(userId);

    let index = 0;
    for (let i = 0; i < LEVEL_THRESHOLDS.length; i += 1) {
      const threshold = LEVEL_THRESHOLDS[i];
      if (threshold !== undefined && total >= threshold) index = i;
    }

    const floor = LEVEL_THRESHOLDS[index] ?? 0;
    const next = LEVEL_THRESHOLDS[index + 1];

    return {
      number: index + 1,
      title: LEVEL_TITLES[index] ?? 'Unknown',
      pointsIntoLevel: total - floor,
      pointsToNext: next === undefined ? null : next - total,
    };
  }
}
