import { defineConfig } from 'vite';
import sri from 'vite-plugin-sri';
import laravel from 'laravel-vite-plugin';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
    plugins: [
        tailwindcss(),
        sri(),
        laravel({
            input: ['resources/css/app.css', 'resources/js/app.js'],
            refresh: true,
        }),
    ],
    server: {
        host: process.env.VITE_HOST ?? '127.0.0.1',
        port: parseInt(process.env.VITE_PORT ?? '5173'),
        strictPort: true,
        hmr: {
            host: '127.0.0.1', // Forces HMR to stay on the local IP
        },
        watch: {
            ignored: ['**/storage/framework/views/**'],
        },
    },
});
