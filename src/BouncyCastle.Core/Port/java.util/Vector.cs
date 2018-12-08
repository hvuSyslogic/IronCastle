using System;
using System.Linq;

namespace org.bouncycastle.Port.java.util
{
    public class Vector : List
    {
        private System.Collections.Generic.List<object> _innerList;

        public Vector()
        {
            _innerList = new System.Collections.Generic.List<object>();
        }

        public Vector(int capacity)
        {
            _innerList = new System.Collections.Generic.List<object>(capacity);
        }

        public bool add(object e)
        {
            _innerList.Add(e);
            return true;
        }

        public bool addAll(Collection c)
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

        public object[] toArray()
        {
            return _innerList.ToArray();
        }

        public object get(int index)
        {
            return _innerList[index];
        }

        public int indexOf(object item)
        {
            return _innerList.IndexOf(item);
        }

        public int lastIndexOf(object o)
        {
            return _innerList.LastIndexOf(o);

        }

        public object remove(int index)
        {
            object prevItem = _innerList[index];
            _innerList.RemoveAt(index);
            return prevItem;
        }

        public object set(int index, object element)
        {
            object prevItem = _innerList[index];
            _innerList[index] = element;
            return prevItem;
        }

        public Iterator iterator()
        {
            throw new NotImplementedException();
        }

        public object elementAt(int i)
        {
            return _innerList[i];
        }

        public object lastElement()
        {
            return _innerList.Last();
        }

        public void removeElementAt(int i)
        {
            _innerList.RemoveAt(i);
        }

        public void addElement(object element)
        {
            _innerList.Add(element);
        }

        public void setElementAt(object obj, int index)
        {
            _innerList[index] = obj;
        }

        public Enumeration elements()
        {
            throw new NotImplementedException();
        }

        public void insertElementAt(object obj, int index)
        {
            _innerList.Insert(index, obj);
        }

        public void copyInto(object[] array)
        {
            var innerArray = _innerList.ToArray();
            Array.Copy(innerArray, array, innerArray.Length);
        }

        public object firstElement()
        {
            return _innerList.First();
        }

        public void removeAllElements()
        {
            _innerList.Clear();
        }

        public bool contains(short? valueOf)
        {
            throw new NotImplementedException();
        }
    }

    public class Vector<T> : List<T>
    {
        private System.Collections.Generic.List<T> _innerList;

        public Vector()
        {
            _innerList = new System.Collections.Generic.List<T>();
        }

        public Vector(int capacity)
        {
            _innerList = new System.Collections.Generic.List<T>(capacity);
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

        public int indexOf(T item)
        {
            return _innerList.IndexOf(item);
        }

        public int lastIndexOf(T o)
        {
            return _innerList.LastIndexOf(o);

        }

        public T remove(int index)
        {
            T prevItem = _innerList[index];
            _innerList.RemoveAt(index);
            return prevItem;
        }

        public T set(int index, T element)
        {
            T prevItem = _innerList[index];
            _innerList[index] = element;
            return prevItem;
        }

        public Iterator<T> iterator()
        {
            throw new NotImplementedException();
        }

        public T elementAt(int i)
        {
            return _innerList[i];
        }

        public T lastElement()
        {
            return _innerList.Last();
        }

        public void removeElementAt(int i)
        {
            _innerList.RemoveAt(i);
        }

        public void addElement(T element)
        {
            _innerList.Add(element);
        }

        public void setElementAt(T obj, int index)
        {
            _innerList[index] = obj;
        }

        public Enumeration<T> elements()
        {
            throw new NotImplementedException();
        }

        public void insertElementAt(T obj, int index)
        {
            _innerList.Insert(index, obj);
        }

        public void copyInto(T[] array)
        {
            var innerArray = _innerList.ToArray();
            Array.Copy(innerArray, array, innerArray.Length);
        }

        public T firstElement()
        {
            return _innerList.First();
        }

        public void removeAllElements()
        {
            _innerList.Clear();
        }
    }
}
