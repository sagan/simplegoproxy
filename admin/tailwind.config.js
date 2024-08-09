/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      // grow-1 ~ grow-6 : flex-grow: 1-6
      flexGrow: {
        1: "1",
        2: "2",
        3: "3",
        4: "4",
        5: "5",
        5: "6",
      },
    },
  },
  plugins: [],
};
