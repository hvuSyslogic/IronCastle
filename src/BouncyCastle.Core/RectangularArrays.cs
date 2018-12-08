//----------------------------------------------------------------------------------------
//	Copyright © 2007 - 2018 Tangible Software Solutions, Inc.
//	This class can be used by anyone provided that the copyright notice remains intact.
//
//	This class includes methods to convert Java rectangular arrays (jagged arrays
//	with inner arrays of the same length).
//----------------------------------------------------------------------------------------
internal static class RectangularArrays
{
    public static byte[][] ReturnRectangularSbyteArray(int size1, int size2)
    {
        byte[][] newArray = new byte[size1][];
        for (int array1 = 0; array1 < size1; array1++)
        {
            newArray[array1] = new byte[size2];
        }

        return newArray;
    }

    public static int[][] ReturnRectangularIntArray(int size1, int size2)
    {
        int[][] newArray = new int[size1][];
        for (int array1 = 0; array1 < size1; array1++)
        {
            newArray[array1] = new int[size2];
        }

        return newArray;
    }

    public static long[][] ReturnRectangularLongArray(int size1, int size2)
    {
        long[][] newArray = new long[size1][];
        for (int array1 = 0; array1 < size1; array1++)
        {
            newArray[array1] = new long[size2];
        }

        return newArray;
    }

    public static long[][][] ReturnRectangularLongArray(int size1, int size2, int size3)
    {
        long[][][] newArray = new long[size1][][];
        for (int array1 = 0; array1 < size1; array1++)
        {
            newArray[array1] = new long[size2][];
            if (size3 > -1)
            {
                for (int array2 = 0; array2 < size2; array2++)
                {
                    newArray[array1][array2] = new long[size3];
                }
            }
        }

        return newArray;
    }

    public static short[][][] ReturnRectangularShortArray(int size1, int size2, int size3)
    {
        short[][][] newArray = new short[size1][][];
        for (int array1 = 0; array1 < size1; array1++)
        {
            newArray[array1] = new short[size2][];
            if (size3 > -1)
            {
                for (int array2 = 0; array2 < size2; array2++)
                {
                    newArray[array1][array2] = new short[size3];
                }
            }
        }

        return newArray;
    }

    public static short[][] ReturnRectangularShortArray(int size1, int size2)
    {
        short[][] newArray = new short[size1][];
        for (int array1 = 0; array1 < size1; array1++)
        {
            newArray[array1] = new short[size2];
        }

        return newArray;
    }

    public static byte[][][] ReturnRectangularSbyteArray(int size1, int size2, int size3)
    {
        byte[][][] newArray = new byte[size1][][];
        for (int array1 = 0; array1 < size1; array1++)
        {
            newArray[array1] = new byte[size2][];
            if (size3 > -1)
            {
                for (int array2 = 0; array2 < size2; array2++)
                {
                    newArray[array1][array2] = new byte[size3];
                }
            }
        }

        return newArray;
    }

    public static char[][] ReturnRectangularCharArray(int size1, int size2)
    {
        char[][] newArray = new char[size1][];
        for (int array1 = 0; array1 < size1; array1++)
        {
            newArray[array1] = new char[size2];
        }

        return newArray;
    }
}