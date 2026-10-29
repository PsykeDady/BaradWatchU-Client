import { Component } from '@angular/core';
import { bootstrapApplication } from '@angular/platform-browser';
import { APP_VERSION } from './app-version';

@Component({
  selector: 'bwu-root',
  standalone: true,
  template: `<main><p class="eyebrow">LOCAL VIEWER · FOUNDATION</p><h1>BaradWatchU</h1><p>Agent status viewer bootstrap · {{ version }}</p><section><h2>Status unavailable</h2><p>The background agent and local status interface are independent. No service connection or audit results are implemented in this bootstrap.</p></section></main>`,
  styleUrl: './styles.css'
})
class AppComponent { readonly version = APP_VERSION; }

bootstrapApplication(AppComponent).catch((error: unknown) => console.error(error));
