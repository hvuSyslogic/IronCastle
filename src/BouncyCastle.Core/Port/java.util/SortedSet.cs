using System;
using System.Linq;

namespace org.bouncycastle.Port.java.util
{
    public class SortedSet<T> : Set<T>
    {
        private readonly System.Collections.Generic.SortedSet<T> _innerSet;

        public SortedSet()
        {
            _innerSet = new System.Collections.Generic.SortedSet<T>();
        }

        protected SortedSet(ArrayList<T> arrayList)
        {
            _innerSet = new System.Collections.Generic.SortedSet<T>();

            addAll(arrayList);
        }

        public Iterator<T> iterator()
        {
            throw new NotImplementedException();
        }

        public bool add(T e)
        {
            return _innerSet.Add(e);
        }

        public bool addAll(Collection<T> c)
        {
            var iterator = c.iterator();

            bool changed = false;

            while (iterator.hasNext())
            {
                if (add(iterator.next()))
                    changed = true;
            }

            return changed;
        }

        public int size()
        {
            return _innerSet.Count;
        }

        public bool isEmpty()
        {
            return _innerSet.Count == 0;
        }

        public T[] toArray()
        {
            return _innerSet.ToArray();
        }

        public bool contains(T value)
        {
            throw new NotImplementedException();
        }

        public bool containsAll(Set<string> otherActions)
        {
            throw new NotImplementedException();
        }
    }
}
