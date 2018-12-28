using System;

namespace org.bouncycastle.Port.java.util
{
    public class ArrayList : List
    {
        public Iterator iterator()
        {
            throw new NotImplementedException();
        }

        public bool add(object e)
        {
            throw new NotImplementedException();
        }

        public bool addAll(Collection c)
        {
            throw new NotImplementedException();
        }

        public int size()
        {
            throw new NotImplementedException();
        }

        public bool isEmpty()
        {
            throw new NotImplementedException();
        }

        public object[] toArray()
        {
            throw new NotImplementedException();
        }

        public object get(int index)
        {
            throw new NotImplementedException();
        }

        public int indexOf(object o)
        {
            throw new NotImplementedException();
        }

        public int lastIndexOf(object o)
        {
            throw new NotImplementedException();
        }

        public object remove(int index)
        {
            throw new NotImplementedException();
        }

        public object set(int index, object element)
        {
            throw new NotImplementedException();
        }
    }

    public class ArrayList<T> : List<T>
    {
        private readonly System.Collections.Generic.List<T> _innerList;

        public ArrayList()
        {
            _innerList = new System.Collections.Generic.List<T>();
        }

        public ArrayList(Collection<T> items)
        {
            _innerList = new System.Collections.Generic.List<T>(items.size());
        }

        public Iterator<T> iterator()
        {
            throw new NotImplementedException();
        }

        public virtual bool add(T e)
        {
            _innerList.Add(e);
            return true;
        }

        public virtual bool addAll(Collection<T> c)
        {
            var iterator = c.iterator();

            while (iterator.hasNext())
            {
                _innerList.Add(iterator.next());
            }

            return true;
        }

        public virtual int size()
        {
            return _innerList.Count;
        }

        public virtual bool isEmpty()
        {
            return _innerList.Count == 0;
        }

        public virtual T[] toArray()
        {
            return _innerList.ToArray();
        }

        public virtual T get(int index)
        {
            return _innerList[index];
        }

        public virtual int indexOf(T o)
        {
            return _innerList.IndexOf(o);
        }

        public int lastIndexOf(T o)
        {
            return _innerList.LastIndexOf(o);
        }

        public T remove(int index)
        {
            T item = _innerList[index];
            _innerList.RemoveAt(index);
            return item;
        }

        public virtual T set(int index, T element)
        {
            T item = _innerList[index];
            _innerList[index] = element;
            return item;
        }

        public void clear()
        {
            throw new NotImplementedException();
        }
    }
}
