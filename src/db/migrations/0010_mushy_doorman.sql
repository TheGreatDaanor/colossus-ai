ALTER TABLE `enumerated_hosts` ADD `endpoint_url` text;--> statement-breakpoint
ALTER TABLE `enumerated_hosts` ADD `last_resolved_at` integer;--> statement-breakpoint
ALTER TABLE `enumerated_hosts` ADD `failed_resolutions` integer DEFAULT 0 NOT NULL;