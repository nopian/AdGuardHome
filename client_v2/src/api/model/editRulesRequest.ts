/**
 * Custom filtering rules editing request.  Rules are compared with the surrounding spaces trimmed.  The rules in `remove` are removed first, then the rules in `add` are appended unless already present.
 */
export interface EditRulesRequest {
    /** Rules to append unless already present. */
    add?: string[];
    /** Rules to remove. */
    remove?: string[];
}
