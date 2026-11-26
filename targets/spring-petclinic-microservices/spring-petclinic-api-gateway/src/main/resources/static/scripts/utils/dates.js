export function today() {
    return toDateInputValue(new Date());
}

export function formatDate(value) {
    if (!value) {
        return '';
    }

    const [year, month, day] = calendarParts(value);
    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    return `${String(year).padStart(4, '0')} ${months[month - 1]} ${String(day).padStart(2, '0')}`;
}

export function toDateInputValue(value) {
    if (!value) {
        return '';
    }

    const [year, month, day] = calendarParts(value);
    return `${String(year).padStart(4, '0')}-${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
}

function calendarParts(value) {
    if (typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value)) {
        const date = new Date(`${value}T00:00:00Z`);
        if (Number.isNaN(date.getTime()) || date.toISOString().slice(0, 10) !== value) {
            throw new RangeError('Invalid calendar date.');
        }
        return value.split('-').map(Number);
    }

    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
        throw new RangeError('Invalid date value.');
    }
    return [date.getFullYear(), date.getMonth() + 1, date.getDate()];
}
