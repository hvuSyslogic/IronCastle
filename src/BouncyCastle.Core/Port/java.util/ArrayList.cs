﻿using System;

namespace org.bouncycastle.Port.java.util
{
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

        public bool add(T e)
        {
            _innerList.Add(e);
            return true;
        }

        public bool addAll(Collection<T> c)
        {
            var iterator = c.iterator();

            while (iterator.hasNext())
            {
                _innerList.Add(iterator.next());
            }

            return true;
        }

        public int size()
        {
            return _innerList.Count;
        }

        public bool isEmpty()
        {
            return _innerList.Count == 0;
        }

        public T[] toArray()
        {
            return _innerList.ToArray();
        }

        public T get(int index)
        {
            return _innerList[index];
        }

        public int indexOf(T o)
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

        public T set(int index, T element)
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