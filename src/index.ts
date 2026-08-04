import { PointsService } from './services/points.js';

const points = new PointsService();
points.award({ userId: 'demo', kind: 'lesson_completed', at: new Date() });

console.warn(`demo has ${points.totalFor('demo')} points`);
console.warn(`level: ${points.levelFor('demo').title}`);
