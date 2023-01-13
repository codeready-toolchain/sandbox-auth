-- Database generated with pgModeler (PostgreSQL Database Modeler).
-- pgModeler version: 0.9.4
-- PostgreSQL version: 13.0
-- Project Site: pgmodeler.io
-- Model Author: ---

-- Database creation must be performed outside a multi lined SQL file. 
-- These commands were put in this file only as a convenience.
-- 
-- -- object: new_database | type: DATABASE --
-- -- DROP DATABASE IF EXISTS new_database;
-- CREATE DATABASE new_database;
-- -- ddl-end --
-- 

-- object: public.identity | type: TABLE --
-- DROP TABLE IF EXISTS public.identity CASCADE;
CREATE TABLE public.identity (
	identity_id uuid NOT NULL,
	username varchar NOT NULL,
	created_at timestamptz NOT NULL,
	updated_at timestamptz,
	deleted_at timestamptz,
	CONSTRAINT identity_pk PRIMARY KEY (identity_id)
);
-- ddl-end --
ALTER TABLE public.identity OWNER TO postgres;
-- ddl-end --


