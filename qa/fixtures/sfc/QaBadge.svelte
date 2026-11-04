<!-- qa sfc fixture: standalone Svelte component (self-written, no fixture imports) -->
<script lang="ts">
  export let label: string;

  export function QaBadge(value: string): string {
    return value.trim().toUpperCase();
  }
</script>

<span class="qa-badge">{label}</span>
