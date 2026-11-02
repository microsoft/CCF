/**
 * @file
 *
 * @brief   Adapter implementation for the QtVariant parser library.
 *
 * Include this file in your program to enable support for QtVariant.
 *
 * This file defines the following classes (not in this order):
 *  - QtVariantAdapter
 *  - QtVariantArray
 *  - QtVariantArrayValueIterator
 *  - QtVariantFrozenValue
 *  - QtVariantObject
 *  - QtVariantObjectMember
 *  - QtVariantObjectMemberIterator
 *  - QtVariantValue
 *
 * Due to the dependencies that exist between these classes, the ordering of
 * class declarations and definitions may be a bit confusing. The best place to
 * start is QtVariantAdapter. This class definition is actually very small,
 * since most of the functionality is inherited from the BasicAdapter class.
 * Most of the classes in this file are provided as template arguments to the
 * inherited BasicAdapter class.
 */

#pragma once

#include <optional>
#include <string>
#include <utility>

#include <QMetaType>
#include <QVariant>
#include <QVariantList>
#include <QVariantMap>

#include <valijson/internal/adapter.hpp>
#include <valijson/internal/basic_adapter.hpp>
#include <valijson/internal/frozen_value.hpp>
#include <valijson/exceptions.hpp>

namespace valijson {
namespace adapters {

class QtVariantAdapter;
class QtVariantArrayValueIterator;
class QtVariantObjectMemberIterator;

typedef std::pair<std::string, QtVariantAdapter> QtVariantObjectMember;

/**
 * @brief  Light weight wrapper for a QtVariant array value.
 *
 * This class is light weight wrapper for a QtVariant array. It provides a
 * minimum set of container functions and typedefs that allow it to be used as
 * an iterable container.
 *
 * An instance of this class contains a single reference to the underlying
 * QtVariant value, assumed to be an array, so there is very little overhead
 * associated with copy construction and passing by value.
 */
class QtVariantArray
{
public:

    typedef QtVariantArrayValueIterator const_iterator;
    typedef QtVariantArrayValueIterator iterator;

    /// Construct a QtVariantArray referencing an empty array.
    QtVariantArray()
      : m_value(emptyArray)
    {
    }

    /**
     * @brief   Construct a QtVariantArray referencing a specific QtVariant
     *          value.
     *
     * @param   value   reference to a QtVariant value
     *
     * Note that this constructor will throw an exception if the value is not
     * an array.
     */
    explicit QtVariantArray(const QVariant &value)
      : m_value(value.toList())
    {
        if (value.typeId() != QMetaType::QVariantList) {
            throwRuntimeError("Value is not an array.");
        }
    }

    /**
     * @brief   Return an iterator for the first element of the array.
     *
     * The iterator return by this function is effectively the iterator
     * returned by the underlying QtVariant implementation.
     */
    QtVariantArrayValueIterator begin() const;

    /**
     * @brief   Return an iterator for one-past the last element of the array.
     *
     * The iterator return by this function is effectively the iterator
     * returned by the underlying QtVariant implementation.
     */
    QtVariantArrayValueIterator end() const;

    /// Return the number of elements in the array
    size_t size() const
    {
        return m_value.size();
    }

private:

    /// Shared QJsonArray instance used to represent empty array.
    static inline const QVariantList emptyArray;

    /// Reference to the contained value
    const QVariantList m_value;
};

/**
 * @brief  Light weight wrapper for a QtVariant object.
 *
 * This class is light weight wrapper for a QtVariant object. It provides a
 * minimum set of container functions and typedefs that allow it to be used as
 * an iterable container.
 *
 * An instance of this class contains a single reference to the underlying
 * QtVariant value, assumed to be an object, so there is very little overhead
 * associated with copy construction and passing by value.
 */
class QtVariantObject
{
public:

    typedef QtVariantObjectMemberIterator const_iterator;
    typedef QtVariantObjectMemberIterator iterator;

    /// Construct a QtVariantObject referencing an empty object singleton.
    QtVariantObject()
      : m_value(emptyObject)
    {
    }

    /**
     * @brief   Construct a QtVariantObject referencing a specific QtVariant
     *          value.
     *
     * @param   value  reference to a QtVariant value
     *
     * Note that this constructor will throw an exception if the value is not
     * an object.
     */
    QtVariantObject(const QVariant &value)
      : m_value(value.toMap())
    {
        if (value.typeId() != QMetaType::QVariantMap) {
            throwRuntimeError("Value is not an object.");
        }
    }

    /**
     * @brief   Return an iterator for this first object member
     *
     * The iterator return by this function is effectively a wrapper around
     * the iterator value returned by the underlying QtVariant implementation.
     */
    QtVariantObjectMemberIterator begin() const;

    /**
     * @brief   Return an iterator for an invalid object member that indicates
     *          the end of the collection.
     *
     * The iterator return by this function is effectively a wrapper around
     * the iterator value returned by the underlying QtVariant implementation.
     */
    QtVariantObjectMemberIterator end() const;

    /**
     * @brief   Return an iterator for the object member with the specified
     *          property name.
     *
     * If an object member with the specified name does not exist, the iterator
     * returned will be the same as the iterator returned by the end() function.
     *
     * @param   propertyName  property name to search for
     */
    QtVariantObjectMemberIterator find(const std::string &propertyName) const;

    /// Returns the number of members belonging to this object.
    size_t size() const
    {
        return m_value.size();
    }

private:

    /// Shared QJsonObject instance used to represent empty object.
    static inline const QVariantMap emptyObject;

    /// Reference to the contained object
    const QVariantMap m_value;
};

/**
 * @brief   Stores an independent copy of a QtVariant value.
 *
 * This class allows a QtVariant value to be stored independent of its original
 * document. QtVariant makes this easy to do, as it does not perform any
 * custom memory management.
 *
 * @see FrozenValue
 */
class QtVariantFrozenValue: public FrozenValue
{
public:

    /**
     * @brief  Make a copy of a QtVariant value
     *
     * @param  source  the QtVariant value to be copied
     */
    explicit QtVariantFrozenValue(QVariant source)
      : m_value(source) { }

    FrozenValue * clone() const override
    {
        return new QtVariantFrozenValue(m_value);
    }

    bool equalTo(const Adapter &other, bool strict) const override;

private:

    /// Stored QtVariant value
    QVariant m_value;
};

/**
 * @brief   Light weight wrapper for a QtVariant value.
 *
 * This class is passed as an argument to the BasicAdapter template class,
 * and is used to provide access to a QtVariant value. This class is responsible
 * for the mechanics of actually reading a QtVariant value, whereas the
 * BasicAdapter class is responsible for the semantics of type comparisons
 * and conversions.
 *
 * The functions that need to be provided by this class are defined implicitly
 * by the implementation of the BasicAdapter template class.
 *
 * @see BasicAdapter
 */
class QtVariantValue
{
public:

    /// Construct a wrapper for the empty object singleton
    QtVariantValue()
      : m_value(emptyObject) { }

    /// Construct a wrapper for a specific QtVariant value
    QtVariantValue(QVariant value)
      : m_value(std::move(value)) { }

    /**
     * @brief   Create a new QtVariantFrozenValue instance that contains the
     *          value referenced by this QtVariantValue instance.
     *
     * @returns pointer to a new QtVariantFrozenValue instance, belonging to the
     *          caller.
     */
    FrozenValue * freeze() const
    {
        return new QtVariantFrozenValue(m_value);
    }

    /**
     * @brief   Optionally return a QtVariantArray instance.
     *
     * If the referenced QtVariant value is an array, this function will return
     * a std::optional containing a QtVariantArray instance referencing the
     * array.
     *
     * Otherwise it will return an empty optional.
     */
    std::optional<QtVariantArray> getArrayOptional() const
    {
        if (isArray()) {
            return std::make_optional(QtVariantArray(m_value));
        }

        return std::optional<QtVariantArray>();
    }

    /**
     * @brief   Retrieve the number of elements in the array
     *
     * If the referenced QtVariant value is an array, this function will
     * retrieve the number of elements in the array and store it in the output
     * variable provided.
     *
     * @param   result  reference to size_t to set with result
     *
     * @returns true if the number of elements was retrieved, false otherwise.
     */
    bool getArraySize(size_t &result) const
    {
        if (isArray()) {
            const QVariantList array = m_value.toList();
            result = array.size();
            return true;
        }

        return false;
    }

    bool getBool(bool &result) const
    {
        if (isBool()) {
            result = m_value.toBool();
            return true;
        }

        return false;
    }

    bool getDouble(double &result) const
    {
        if (isDouble()) {
            result = m_value.toDouble();
            return true;
        }

        return false;
    }

    bool getInteger(int64_t &result) const
    {
        if (isInteger()) {
            result = m_value.toLongLong();
            return true;
        }

        return false;
    }

    /**
     * @brief   Optionally return a QtVariantObject instance.
     *
     * If the referenced QtVariant value is an object, this function will return a
     * std::optional containing a QtVariantObject instance referencing the
     * object.
     *
     * Otherwise it will return an empty optional.
     */
    std::optional<QtVariantObject> getObjectOptional() const
    {
        if (isObject()) {
            return std::make_optional(QtVariantObject(m_value));
        }

        return std::optional<QtVariantObject>();
    }

    /**
     * @brief   Retrieve the number of members in the object
     *
     * If the referenced QtVariant value is an object, this function will
     * retrieve the number of members in the object and store it in the output
     * variable provided.
     *
     * @param   result  reference to size_t to set with result
     *
     * @returns true if the number of members was retrieved, false otherwise.
     */
    bool getObjectSize(size_t &result) const
    {
        if (isObject()) {
            const QVariantMap &object = m_value.toMap();
            result = object.size();
            return true;
        }

        return false;
    }

    bool getString(std::string &result) const
    {
        if (isString()) {
            result = m_value.toString().toStdString();
            return true;
        }

        return false;
    }

    static bool hasStrictTypes()
    {
        return true;
    }

    bool isArray() const
    {
        return m_value.typeId() == QMetaType::QVariantList;
    }

    bool isBool() const
    {
        return m_value.typeId() == QMetaType::Bool;
    }

    bool isDouble() const
    {
        static const QList<int> types{
            QMetaType::Double,
            QMetaType::Float
        };
        return types.contains(m_value.typeId());
    }

    bool isInteger() const
    {
        static const QList<int> types{
            QMetaType::Int,
            QMetaType::UInt,
            QMetaType::Long,
            QMetaType::LongLong,
            QMetaType::Short,
            QMetaType::UShort,
            QMetaType::ULongLong,
            QMetaType::ULong,
            QMetaType::Char,
            QMetaType::Char16,
            QMetaType::Char32,
            QMetaType::SChar,
            QMetaType::UChar
        };
        return types.contains(m_value.typeId());
    }

    bool isNull() const
    {
        return m_value.isNull();
    }

    bool isNumber() const
    {
        return isDouble() || isInteger();
    }

    bool isObject() const
    {
        return m_value.typeId() == QMetaType::QVariantMap;
    }

    bool isString() const
    {
        return m_value.typeId() == QMetaType::QString;
    }

private:

    /// Shared QtVariant value instance used to represent an empty object
    static inline const QVariant emptyObject;

    /// Reference to the contained QtVariant value.
    const QVariant m_value;
};

/**
 * @brief   An implementation of the Adapter interface supporting QtVariant.
 *
 * This class is defined in terms of the BasicAdapter template class, which
 * helps to ensure that all of the Adapter implementations behave consistently.
 *
 * @see Adapter
 * @see BasicAdapter
 */
class QtVariantAdapter:
    public BasicAdapter<QtVariantAdapter,
                        QtVariantArray,
                        QtVariantObjectMember,
                        QtVariantObject,
                        QtVariantValue>
{
public:

    /// Construct a QtVariantAdapter that contains an empty object
    QtVariantAdapter()
      : BasicAdapter() { }

    /// Construct a QtVariantAdapter containing a specific QVariant value
    QtVariantAdapter(const QVariant &value)
      : BasicAdapter(value) { }
};

/**
 * @brief   Class for iterating over values held in a JSON array.
 *
 * This class provides a JSON array iterator that dereferences as an instance of
 * QtVariantAdapter representing a value stored in the array.
 *
 * @see QtVariantArray
 */
class QtVariantArrayValueIterator
{
public:
    using iterator_category = std::bidirectional_iterator_tag;
    using value_type = QtVariantAdapter;
    using difference_type = QtVariantAdapter;
    using pointer = QtVariantAdapter*;
    using reference = QtVariantAdapter&;

    /**
     * @brief   Construct a new QtVariantArrayValueIterator using an existing
     *          QVariant iterator.
     *
     * @param   itr  QVariant iterator to store
     */
    QtVariantArrayValueIterator(const QList<QVariant>::const_iterator &itr)
      : m_itr(itr) { }

    /// Returns a QtVariantAdapter that contains the value of the current
    /// element.
    QtVariantAdapter operator*() const
    {
        return QtVariantAdapter(*m_itr);
    }

    DerefProxy<QtVariantAdapter> operator->() const
    {
        return DerefProxy<QtVariantAdapter>(**this);
    }

    /**
     * @brief   Compare this iterator against another iterator.
     *
     * Note that this directly compares the iterators, not the underlying
     * values, and assumes that two identical iterators will point to the same
     * underlying object.
     *
     * @param   other  iterator to compare against
     *
     * @returns true   if the iterators are equal, false otherwise.
     */
    bool operator==(const QtVariantArrayValueIterator &other) const
    {
        return m_itr == other.m_itr;
    }

    bool operator!=(const QtVariantArrayValueIterator &other) const
    {
        return !(m_itr == other.m_itr);
    }

    const QtVariantArrayValueIterator& operator++()
    {
        m_itr++;

        return *this;
    }

    QtVariantArrayValueIterator operator++(int)
    {
        QtVariantArrayValueIterator iterator_pre(m_itr);
        ++(*this);
        return iterator_pre;
    }

    const QtVariantArrayValueIterator& operator--()
    {
        m_itr--;

        return *this;
    }

    void advance(std::ptrdiff_t n)
    {
        m_itr += n;
    }

private:

    QList<QVariant>::const_iterator m_itr;
};

/**
 * @brief   Class for iterating over the members belonging to a JSON object.
 *
 * This class provides a JSON object iterator that dereferences as an instance
 * of QtVariantObjectMember representing one of the members of the object. It
 * has been implemented using the boost iterator_facade template.
 *
 * @see QtVariantObject
 * @see QtVariantObjectMember
 */
class QtVariantObjectMemberIterator
{
public:
    using iterator_category = std::bidirectional_iterator_tag;
    using value_type = QtVariantObjectMember;
    using difference_type = QtVariantObjectMember;
    using pointer = QtVariantObjectMember*;
    using reference = QtVariantObjectMember&;

    /**
     * @brief   Construct an iterator from a QtVariant iterator.
     *
     * @param   itr  QtVariant iterator to store
     */
    QtVariantObjectMemberIterator(
        const QMap<QString, QVariant>::const_iterator &itr)
      : m_itr(itr) { }

    /**
     * @brief   Returns a QtVariantObjectMember that contains the key and value
     *          belonging to the object member identified by the iterator.
     */
    QtVariantObjectMember operator*() const
    {
        std::string key = m_itr.key().toStdString();
        return QtVariantObjectMember(key, m_itr.value());
    }

    DerefProxy<QtVariantObjectMember> operator->() const
    {
        return DerefProxy<QtVariantObjectMember>(**this);
    }

    /**
     * @brief   Compare this iterator with another iterator.
     *
     * Note that this directly compares the iterators, not the underlying
     * values, and assumes that two identical iterators will point to the same
     * underlying object.
     *
     * @param   other  Iterator to compare with
     *
     * @returns true if the underlying iterators are equal, false otherwise
     */
    bool operator==(const QtVariantObjectMemberIterator &other) const
    {
        return m_itr == other.m_itr;
    }

    bool operator!=(const QtVariantObjectMemberIterator &other) const
    {
        return !(m_itr == other.m_itr);
    }

    const QtVariantObjectMemberIterator& operator++()
    {
        m_itr++;
        return *this;
    }

    QtVariantObjectMemberIterator operator++(int)
    {
        QtVariantObjectMemberIterator iterator_pre(m_itr);
        ++(*this);
        return iterator_pre;
    }

    const QtVariantObjectMemberIterator& operator--()
    {
        m_itr--;

        return *this;
    }

private:

    /// Internal copy of the original QtVariant iterator
    QMap<QString, QVariant>::const_iterator m_itr;
};

/// Specialisation of the AdapterTraits template struct for QtVariantAdapter.
template<>
struct AdapterTraits<valijson::adapters::QtVariantAdapter>
{
    typedef QVariant DocumentType;

    static std::string adapterName()
    {
        return "QtVariantAdapter";
    }
};

inline bool QtVariantFrozenValue::equalTo(const Adapter &other, bool strict) const
{
    return QtVariantAdapter(m_value).equalTo(other, strict);
}

inline QtVariantArrayValueIterator QtVariantArray::begin() const
{
    return m_value.begin();
}

inline QtVariantArrayValueIterator QtVariantArray::end() const
{
    return m_value.end();
}

inline QtVariantObjectMemberIterator QtVariantObject::begin() const
{
    return m_value.begin();
}

inline QtVariantObjectMemberIterator QtVariantObject::end() const
{
    return m_value.end();
}

inline QtVariantObjectMemberIterator QtVariantObject::find(
    const std::string &propertyName) const
{
    return m_value.find(QString::fromStdString(propertyName));
}

}  // namespace adapters
}  // namespace valijson
