using org.bouncycastle.Port;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.pqc.crypto.gmss
{

	using Arrays = org.bouncycastle.util.Arrays;

	public class GMSSUtils
	{
		internal static GMSSLeaf[] clone(GMSSLeaf[] data)
		{
			if (data == null)
			{
				return null;
			}
			GMSSLeaf[] copy = new GMSSLeaf[data.Length];

			JavaSystem.arraycopy(data, 0, copy, 0, data.Length);

			return copy;
		}

		internal static GMSSRootCalc[] clone(GMSSRootCalc[] data)
		{
			if (data == null)
			{
				return null;
			}
			GMSSRootCalc[] copy = new GMSSRootCalc[data.Length];

			JavaSystem.arraycopy(data, 0, copy, 0, data.Length);

			return copy;
		}

		internal static GMSSRootSig[] clone(GMSSRootSig[] data)
		{
			if (data == null)
			{
				return null;
			}
			GMSSRootSig[] copy = new GMSSRootSig[data.Length];

			JavaSystem.arraycopy(data, 0, copy, 0, data.Length);

			return copy;
		}

		internal static byte[][] clone(byte[][] data)
		{
			if (data == null)
			{
				return null;
			}
			byte[][] copy = new byte[data.Length][];

			for (int i = 0; i != data.Length; i++)
			{
				copy[i] = Arrays.clone(data[i]);
			}

			return copy;
		}

		internal static byte[][][] clone(byte[][][] data)
		{
			if (data == null)
			{
				return null;
			}
			byte[][][] copy = new byte[data.Length][][];

			for (int i = 0; i != data.Length; i++)
			{
				copy[i] = clone(data[i]);
			}

			return copy;
		}

		internal static Treehash[] clone(Treehash[] data)
		{
			if (data == null)
			{
				return null;
			}
			Treehash[] copy = new Treehash[data.Length];

			JavaSystem.arraycopy(data, 0, copy, 0, data.Length);

			return copy;
		}

		internal static Treehash[][] clone(Treehash[][] data)
		{
			if (data == null)
			{
				return null;
			}
			Treehash[][] copy = new Treehash[data.Length][];

			for (int i = 0; i != data.Length; i++)
			{
				copy[i] = clone(data[i]);
			}

			return copy;
		}

		internal static Vector[] clone(Vector[] data)
		{
			if (data == null)
			{
				return null;
			}
			Vector[] copy = new Vector[data.Length];

			for (int i = 0; i != data.Length; i++)
			{
				copy[i] = new Vector();
				for (Enumeration en = data[i].elements(); en.hasMoreElements();)
				{
					copy[i].addElement(en.nextElement());
				}
			}

			return copy;
		}

		internal static Vector[][] clone(Vector[][] data)
		{
			if (data == null)
			{
				return null;
			}
			Vector[][] copy = new Vector[data.Length][];

			for (int i = 0; i != data.Length; i++)
			{
				copy[i] = clone(data[i]);
			}

			return copy;
		}
	}

}