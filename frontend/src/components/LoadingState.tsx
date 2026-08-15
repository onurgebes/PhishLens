export function LoadingState() {
  return (
    <div className="flex flex-col items-center justify-center p-8">
      <div className="relative w-16 h-16">
        <div className="absolute inset-0 border-4 border-cyber-accent border-t-transparent rounded-full animate-spin"></div>
        <div className="absolute inset-2 border-4 border-cyber-accent border-t-transparent rounded-full animate-spin" style={{ animationDirection: 'reverse', animationDuration: '1.5s' }}></div>
      </div>
      <p className="mt-4 text-cyber-light text-lg">Analyzing email...</p>
      <p className="mt-2 text-cyber-gray text-sm">This may take a few seconds</p>
    </div>
  );
}
