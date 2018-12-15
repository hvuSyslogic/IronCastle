using System;

namespace org.bouncycastle.Port.java.util
{
    public class TreeSet : SortedSet
    {
        private ArrayList arrayList;

        public TreeSet(ArrayList arrayList)
        {
            this.arrayList = arrayList;
        }
    }

    public class SortedSet : Set
    {
        public Iterator iterator()
        {
            throw new System.NotImplementedException();
        }

        public bool add(object e)
        {
            throw new System.NotImplementedException();
        }

        public bool addAll(Collection c)
        {
            throw new System.NotImplementedException();
        }

        internal void addAll(ArrayList arrayList)
        {
            throw new NotImplementedException();
        }

        public int size()
        {
            throw new System.NotImplementedException();
        }

        public bool isEmpty()
        {
            throw new System.NotImplementedException();
        }

        public object[] toArray()
        {
            throw new System.NotImplementedException();
        }

        public void retainAll(Set otherNames)
        {
            throw new System.NotImplementedException();
        }

        public bool contains(object value)
        {
            throw new System.NotImplementedException();
        }
    }

    public class TreeSet<T> : SortedSet<T>
    {

        public TreeSet(ArrayList<T> arrayList):base(arrayList)
        {

        }
    }
}
