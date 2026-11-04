<!-- qa sfc fixture: standalone Vue component (self-written, no fixture imports) -->
<template>
  <section class="qa-panel">
    <h2>{{ heading }}</h2>
  </section>
</template>

<script setup lang="ts">
import { computed } from "vue";

const props = defineProps<{ heading: string }>();

const QaPanel = (value: { heading: string }): string => value.heading.trim();

const qaPanelLabel = computed(() => QaPanel(props));
</script>
