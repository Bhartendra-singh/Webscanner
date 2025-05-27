function searchHeader(results, headerName) {
  return results.find(r => r.header.toLowerCase() === headerName.toLowerCase()) || null;
}

// Example usage
const searchTerm = "X-Frame-Options";
const found = searchHeader(scanResults, searchTerm);

if (found) {
  console.log(`Found: ${found.header} is ${found.risk} risk`);
} else {
  console.log("Header not found");
}