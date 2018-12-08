using System;

namespace org.bouncycastle.Port.java.util
{
    public class Stack<T> : Vector<T>
    {
        public T push(T item)
        {
            addElement(item);

            return item;
        }

        public T pop()
        {
            T obj;
            int len = size();

            obj = peek();
            removeElementAt(len - 1);

            return obj;
        }

        public T peek()
        {
            int len = size();

            if (len == 0)
                throw new EmptyStackException();
            return elementAt(len - 1);
        }

        public bool empty()
        {
            throw new NotImplementedException();
        }
    }
}
