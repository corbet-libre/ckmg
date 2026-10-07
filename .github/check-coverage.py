#!/usr/bin/env python3
"""Gate exact LLVM line and branch counts, without rounded percentages."""
import json
import sys
from pathlib import Path


def check(report):
    if report.get('type') != 'llvm.coverage.json.export' or not report.get('data'):
        raise ValueError('Expected a nonempty LLVM coverage export')
    failures = []
    lines = 0
    for unit in report['data']:
        totals = unit['totals']
        for metric in ('lines', 'branches'):
            value = totals[metric]
            count, covered = value['count'], value['covered']
            if not isinstance(count, int) or not isinstance(covered, int) or not 0 <= covered <= count:
                raise ValueError(f'Invalid {metric} counts')
            if metric == 'lines':
                lines += count
            print(f'{metric}: {covered}/{count}')
            if covered != count:
                failures.append(f'{metric}: {count - covered} uncovered')
    if lines == 0:
        raise ValueError('Empty line coverage cannot pass')
    if failures:
        for unit in report['data']:
            for entry in unit.get('files', []):
                summary = entry.get('summary', {})
                missed = {m: summary[m]['count'] - summary[m]['covered'] for m in ('lines', 'branches') if m in summary}
                if any(missed.values()):
                    by_line = {}
                    for seg in entry.get('segments', []):
                        if len(seg) > 4 and seg[3]:
                            by_line[seg[0]] = max(by_line.get(seg[0], 0), seg[2])
                    zero = sorted(line for line, count in by_line.items() if count == 0)
                    print(f"zero-count regions {entry.get('filename')}: lines {zero}")
                    arms = [(b[0], b[4], b[5]) for b in entry.get('branches', []) if len(b) > 5 and (b[4] == 0 or b[5] == 0)]
                    print(f"zero-count branch arms {entry.get('filename')}: (line, true, false) {arms}")
                    print(f"uncovered {entry.get('filename')}: lines {missed.get('lines', 0)}, branches {missed.get('branches', 0)}")
        raise ValueError('; '.join(failures))


if __name__ == '__main__':
    try:
        check(json.loads(Path(sys.argv[1]).read_text()))
    except (ValueError, KeyError, TypeError) as error:
        sys.exit(f'Coverage gate: {error}')
