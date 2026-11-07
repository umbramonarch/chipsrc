// qa sfc fixture: standalone React component (self-written, no fixture imports)
import { useState } from "react";

function qaFormatCount(value) {
  return String(value).padStart(2, "0");
}

export function QaCounter({ start }) {
  const [count, setCount] = useState(start ?? 0);
  return (
    <section className="qa-counter">
      <button type="button" onClick={() => setCount(count + 1)}>
        {qaFormatCount(count)}
      </button>
    </section>
  );
}

export default QaCounter;
