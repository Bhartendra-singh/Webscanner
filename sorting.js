// Define custom risk order
const riskOrder = { HIGH: 1, MEDIUM: 2, LOW: 3 };

function sortByRisk(results) {
  return results.sort((a, b) => riskOrder[a.risk] - riskOrder[b.risk]);
}

// Example usage
const sortedResults = sortByRisk(scanResults);
console.log(" Sorted Results by Risk Level:");
sortedResults.forEach(result => {
  console.log(`${result.header} - ${result.risk}`);
});