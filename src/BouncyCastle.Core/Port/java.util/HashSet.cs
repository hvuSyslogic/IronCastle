using System;
using System.Linq;

namespace org.bouncycastle.Port.java.util
{
    public class HashSet : Set
    {
        private System.Collections.Generic.HashSet<object> _innerHashSet;
        private Set permitted;

        public HashSet()
        {
            _innerHashSet = new System.Collections.Generic.HashSet<object>();
        }

        public HashSet(Set permitted)
        {
            this.permitted = permitted;
        }

        public Iterator iterator()
        {
            throw new NotImplementedException();
        }

        public bool add(object e)
        {
            if (!_innerHashSet.Contains(e))
            {
                _innerHashSet.Add(e);
                return true;
            }

            return false;
        }

        public bool addAll(Collection c)
        {
            var iterator = c.iterator();

            bool changed = false;
            while (iterator.hasNext())
            {
                var item = iterator.next();
                if (!_innerHashSet.Contains(item))
                {
                    _innerHashSet.Add(item);
                    changed = true;
                }
            }

            return changed;
        }

        public int size()
        {
            return _innerHashSet.Count;
        }

        public bool isEmpty()
        {
            return _innerHashSet.Count == 0;
        }

        public object[] toArray()
        {
            return _innerHashSet.ToArray();
        }

        public void retainAll(Set otherNames)
        {
            throw new NotImplementedException();
        }

        public bool contains(object value)
        {
            throw new NotImplementedException();
        }
    }


    public class HashSet<T> : Set<T>
    {
        private System.Collections.Generic.HashSet<T> _innerHashSet;

        public HashSet()
        {
            _innerHashSet = new System.Collections.Generic.HashSet<T>();
        }

        public Iterator<T> iterator()
        {
            throw new NotImplementedException();
        }

        public bool add(T e)
        {
            if (!_innerHashSet.Contains(e))
            {
                _innerHashSet.Add(e);
                return true;
            }

            return false;
        }

        public bool addAll(Collection<T> c)
        {
            var iterator = c.iterator();

            bool changed = false;
            while (iterator.hasNext())
            {
                var item = iterator.next();
                if (!_innerHashSet.Contains(item))
                {
                    _innerHashSet.Add(item);
                    changed = true;
                }
            }

            return changed;
        }

        public int size()
        {
            return _innerHashSet.Count;
        }

        public bool isEmpty()
        {
            return _innerHashSet.Count == 0;
        }

        public T[] toArray()
        {
            return _innerHashSet.ToArray();
        }

        public bool contains(T value)
        {
            throw new NotImplementedException();
        }
    }
}
