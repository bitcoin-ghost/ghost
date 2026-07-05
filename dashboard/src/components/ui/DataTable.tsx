'use client';

import { useState } from 'react';
import {
  useReactTable,
  getCoreRowModel,
  getSortedRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  flexRender,
  type ColumnDef,
  type SortingState,
  type ColumnFiltersState,
} from '@tanstack/react-table';
import { Input } from './Input';
import { Button } from './Button';
import { SkeletonTable } from './Skeleton';
import { EmptyState } from './EmptyState';

interface DataTableProps<TData, TValue> {
  columns: ColumnDef<TData, TValue>[];
  data: TData[];
  searchPlaceholder?: string;
  searchColumn?: string;
  pageSize?: number;
  showPagination?: boolean;
  emptyMessage?: string;
  emptyIcon?: React.ReactNode;
  emptyDescription?: string;
  loading?: boolean;
  loadingRows?: number;
}

export function DataTable<TData, TValue>({
  columns,
  data,
  searchPlaceholder = 'Search...',
  searchColumn,
  pageSize = 10,
  showPagination = true,
  emptyMessage = 'No data available',
  emptyIcon,
  emptyDescription,
  loading,
  loadingRows = 5,
}: DataTableProps<TData, TValue>) {
  const [sorting, setSorting] = useState<SortingState>([]);
  const [columnFilters, setColumnFilters] = useState<ColumnFiltersState>([]);

  // eslint-disable-next-line react-hooks/incompatible-library
  const table = useReactTable({
    data,
    columns,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    onSortingChange: setSorting,
    onColumnFiltersChange: setColumnFilters,
    state: { sorting, columnFilters },
    initialState: { pagination: { pageSize } },
  });

  if (loading) {
    return (
      <div className="space-y-4">
        {searchColumn && (
          <div className="max-w-sm">
            <div className="h-10 bg-gray-800 rounded-lg animate-pulse" />
          </div>
        )}
        <SkeletonTable rows={loadingRows} cols={columns.length} />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Search input */}
      {searchColumn && (
        <div className="max-w-sm">
          <Input
            placeholder={searchPlaceholder}
            value={(table.getColumn(searchColumn)?.getFilterValue() as string) ?? ''}
            onChange={(e) => table.getColumn(searchColumn)?.setFilterValue(e.target.value)}
          />
        </div>
      )}

      {/* Table */}
      <div className="rounded-lg border border-gray-800 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-800/50">
              {table.getHeaderGroups().map((headerGroup) => (
                <tr key={headerGroup.id}>
                  {headerGroup.headers.map((header) => (
                    <th
                      key={header.id}
                      className={`
                        px-4 py-3 text-left text-sm font-medium text-gray-400
                        ${header.column.getCanSort() ? 'cursor-pointer hover:text-gray-200 select-none' : ''}
                      `}
                      onClick={header.column.getToggleSortingHandler()}
                    >
                      <div className="flex items-center gap-2">
                        {header.isPlaceholder
                          ? null
                          : flexRender(header.column.columnDef.header, header.getContext())}
                        {header.column.getIsSorted() && (
                          <span className="text-orange-400">
                            {header.column.getIsSorted() === 'asc' ? '\u2191' : '\u2193'}
                          </span>
                        )}
                      </div>
                    </th>
                  ))}
                </tr>
              ))}
            </thead>
            <tbody className="divide-y divide-gray-800">
              {table.getRowModel().rows.length === 0 ? (
                <tr>
                  <td colSpan={columns.length}>
                    <EmptyState
                      icon={emptyIcon}
                      title={emptyMessage}
                      description={emptyDescription}
                    />
                  </td>
                </tr>
              ) : (
                table.getRowModel().rows.map((row) => (
                  <tr
                    key={row.id}
                    className="hover:bg-gray-800/30 transition-colors"
                  >
                    {row.getVisibleCells().map((cell) => (
                      <td key={cell.id} className="px-4 py-3 text-sm text-gray-100">
                        {flexRender(cell.column.columnDef.cell, cell.getContext())}
                      </td>
                    ))}
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Pagination */}
      {showPagination && table.getPageCount() > 1 && (
        <div className="flex items-center justify-between">
          <span className="text-sm text-gray-400">
            Page {table.getState().pagination.pageIndex + 1} of {table.getPageCount()}
            {' \u00b7 '}
            {table.getFilteredRowModel().rows.length} total rows
          </span>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => table.previousPage()}
              disabled={!table.getCanPreviousPage()}
            >
              Previous
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => table.nextPage()}
              disabled={!table.getCanNextPage()}
            >
              Next
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

// Helper for creating common column types
export function createColumn<T>(
  accessorKey: keyof T & string,
  header: string,
  options?: Partial<ColumnDef<T, unknown>>
): ColumnDef<T, unknown> {
  return {
    accessorKey,
    header,
    ...options,
  };
}

// Common cell renderers
export function formatBtc(sats: number): string {
  return (sats / 100_000_000).toFixed(8);
}

// Auto-scaling hashrate formatter. `digits` controls decimal places (default 2);
// pass 0 for the global network-hashrate tile, which reaches EH/s magnitudes and
// needs to stay compact so the unit isn't truncated. Scales up to ZH/s so
// exahash-scale network estimates keep their unit rather than overflowing PH/s.
export function formatHashrate(hashrate: number, digits = 2): string {
  if (hashrate >= 1e21) return `${(hashrate / 1e21).toFixed(digits)} ZH/s`;
  if (hashrate >= 1e18) return `${(hashrate / 1e18).toFixed(digits)} EH/s`;
  if (hashrate >= 1e15) return `${(hashrate / 1e15).toFixed(digits)} PH/s`;
  if (hashrate >= 1e12) return `${(hashrate / 1e12).toFixed(digits)} TH/s`;
  if (hashrate >= 1e9) return `${(hashrate / 1e9).toFixed(digits)} GH/s`;
  if (hashrate >= 1e6) return `${(hashrate / 1e6).toFixed(digits)} MH/s`;
  if (hashrate >= 1e3) return `${(hashrate / 1e3).toFixed(digits)} KH/s`;
  return `${hashrate.toFixed(digits)} H/s`;
}

export function formatDuration(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const mins = Math.floor((seconds % 3600) / 60);

  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${mins}m`;
  return `${mins}m`;
}

export function truncateId(id: string, chars = 6): string {
  if (id.length <= chars * 2 + 3) return id;
  return `${id.slice(0, chars)}...${id.slice(-chars)}`;
}
