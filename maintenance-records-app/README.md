# Maintenance Records: tap-through prototype

Static site (no build step). 80 screens linked together, starting at Sign in.

## Deploy on Vercel
1. Unzip, then in the folder run `npx vercel` (Framework preset: Other, no build command, output directory `.`).
   Or drag the folder into vercel.com/new.
2. Open the URL. Use the left menu to jump to any screen, or tap through from Sign in.

## Supabase
`supabase/schema_and_seed.sql` is the database (tables, row level security, simple test data).
Run it in Supabase > SQL Editor. The prototype screens are not connected to it yet:
they show fixed example text.
