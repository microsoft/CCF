#pragma once

#include <deque>
#include <string>
#include <utility>
#include <vector>

namespace valijson {

/**
 * @brief  Class that encapsulates the storage of validation errors.
 *
 * This class maintains an internal FIFO queue of errors that are reported
 * during validation. Errors are pushed on to the back of an internal
 * queue, and can retrieved by popping them from the front of the queue.
 */
class ValidationResults
{
public:

    enum Kind
    {
        kArray,
        kObject
    };

    struct Segment
    {
        /// What kind of traversal is this?
        Kind kind;

        /// Index or name of property to traverse into
        std::string name;
    };

    typedef std::vector<Segment> Path;

    /**
     * @brief  Describes a validation error.
     *
     * This struct is used to pass around the path and description of a
     * validation error. The path is stored in two formats. First is 'context',
     * a legacy format, used only by Valijson. Second is JSON Pointer format,
     * which is defined in RFC 6901.
     */
    struct Error
    {
        /**
         * Path to the node that failed validation (LEGACY).
         *
         * @deprecated use \c jsonPointer instead
         */
        std::vector<std::string> context;

        /// A detailed description of the validation error.
        std::string description;

        /// JSON Pointer identifying the node that failed validation.
        std::string jsonPointer;
    };

    /**
     * @brief  Return begin iterator for results in the queue.
     */
    std::deque<Error>::const_iterator begin() const
    {
        return m_errors.begin();
    }

    /**
     * @brief  Return end iterator for results in the queue.
     */
    std::deque<Error>::const_iterator end() const
    {
        return m_errors.end();
    }

    /**
     * @brief  Return the number of errors in the queue.
     */
    size_t numErrors() const
    {
        return m_errors.size();
    }

    /**
     * @brief  Copy an Error and push it on to the back of the queue.
     *
     * @param  error  Reference to an Error object to be copied.
     */
    void pushError(const Error &error)
    {
        m_errors.push_back(error);
    }

    /**
     * @brief  Push an error onto the back of the queue.
     *
     * @param  path         Path of the validation error.
     * @param  description  Description of the validation error.
     */
    void
    pushError(const Path &path, const std::string &description)
    {
        // construct legacy context
        //  e.g. <root>["my_object"][1]["some_property"]
        const std::vector<std::string> context = toContext(path);

        // construct JSON pointer
        //  e.g. /my_object/1/some_property
        const std::string jsonPointer = toJsonPointer(path);

        m_errors.push_back({context, description, jsonPointer});
    }

    /**
     * @brief  Pop an error from the front of the queue.
     *
     * @param  error  Reference to an Error object to populate.
     *
     * @returns  true if an Error was popped, false otherwise.
     */
    bool
    popError(Error &error)
    {
        if (m_errors.empty()) {
            return false;
        }

        error = m_errors.front();
        m_errors.pop_front();
        return true;
    }

private:

    /// FIFO queue of validation errors that have been reported
    std::deque<Error> m_errors;

    static std::string escapeJsonPointerToken(const std::string &token)
    {
        std::string escaped;
        escaped.reserve(token.size());

        for (const char ch : token) {
            switch (ch) {
            case '~':
                escaped.append("~0");
                break;
            case '/':
                escaped.append("~1");
                break;
            default:
                escaped.push_back(ch);
                break;
            }
        }

        return escaped;
    }

    /**
     * @brief  Convert a path to a legacy v1.0 context string
     *
     * e.g. <root>["my_object"][1]["some_property"]
     */
    static std::vector<std::string> toContext(const Path &path)
    {
        auto context = std::vector<std::string>();
        context.push_back("<root>");
        for (const auto &segment : path) {
            if (segment.kind == kObject) {
                std::string s("[\"");
                s += segment.name;
                s += "\"]";
                context.push_back(s);
            } else {
                std::string s("[");
                s += segment.name;
                s += "]";
                context.push_back(s);
            }
        }

        return context;
    }

    /**
     * Convert a path to a JSON Pointer
     *
     * e.g. /my_object/1/some_property
     */
    static std::string toJsonPointer(const Path &path)
    {
        std::string pointer;
        for (const auto &segment : path) {
            pointer.push_back('/');
            pointer.append(escapeJsonPointerToken(segment.name));
        }

        return pointer;
    }
};

} // namespace valijson
