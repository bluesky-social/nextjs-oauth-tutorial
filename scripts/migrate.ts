import { getMigrator } from "@/lib/db/migrations";

async function migrate() {
  const migrator = getMigrator();
  const { error } = await migrator.migrateToLatest();
  if (error) throw error;
  console.log("Migrations complete.");
}

migrate();
