// Fire the CLI's first 30s deadline only once maintenance reaches its status
// publication, inside the service's cancellation handler. Other timers stay real.
const schedule = globalThis.setTimeout;
let startup;
let captured = false;
globalThis.setTimeout = (callback, milliseconds, ...args) => {
	const timer = schedule(callback, milliseconds, ...args);
	if (milliseconds === 30_000 && !captured) {
		captured = true;
		startup = { callback, args, timer };
	}
	return timer;
};
const write = process.stdout.write;
process.stdout.write = function (...args) {
	if (startup && String(args[0]).startsWith('{"type":"status"')) {
		const deadline = startup;
		startup = undefined;
		clearTimeout(deadline.timer);
		deadline.callback(...deadline.args);
	}
	return Reflect.apply(write, this, args);
};
