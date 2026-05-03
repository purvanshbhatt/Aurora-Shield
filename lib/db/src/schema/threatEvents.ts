import { pgTable, serial, text, real, timestamp, pgEnum } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const threatTypeEnum = pgEnum("threat_type", [
  "prompt_injection",
  "phishing",
  "suspicious_url",
]);

export const riskLevelEnum = pgEnum("risk_level", [
  "safe",
  "low",
  "medium",
  "high",
  "critical",
]);

export const threatEventsTable = pgTable("threat_events", {
  id: serial("id").primaryKey(),
  type: threatTypeEnum("type").notNull(),
  riskLevel: riskLevelEnum("risk_level").notNull(),
  riskScore: real("risk_score").notNull(),
  summary: text("summary").notNull(),
  context: text("context").notNull().default(""),
  detectedAt: timestamp("detected_at").notNull().defaultNow(),
});

export const insertThreatEventSchema = createInsertSchema(threatEventsTable).omit({ id: true, detectedAt: true });
export type InsertThreatEvent = z.infer<typeof insertThreatEventSchema>;
export type ThreatEvent = typeof threatEventsTable.$inferSelect;
