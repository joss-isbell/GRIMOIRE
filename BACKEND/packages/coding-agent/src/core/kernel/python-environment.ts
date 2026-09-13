/** Isolate managed Python from the launching shell; explicit kernel env overrides still apply. */
export function kernelPythonEnvironment(base: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
	const env: NodeJS.ProcessEnv = { ...base, PYTHONUTF8: "1", PYTHONNOUSERSITE: "1", PYTHONSAFEPATH: "1" };
	delete env.PYTHONHOME;
	delete env.PYTHONPATH;
	return env;
}
