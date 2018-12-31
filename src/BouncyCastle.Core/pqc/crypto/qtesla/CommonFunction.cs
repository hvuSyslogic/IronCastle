
using BouncyCastle.Core.Port.java.lang;

namespace org.bouncycastle.pqc.crypto.qtesla
{
	public class CommonFunction
	{

		/// <summary>
		///**************************************************************************************************
		/// Description:	Checks Whether the Two Parts of Arrays are Equal to Each Other
		/// </summary>
		/// <param name="left">            Left Array </param>
		/// <param name="leftOffset">        Starting Point of the Left Array </param>
		/// <param name="right">            Right Array </param>
		/// <param name="rightOffset">        Starting Point of the Right Array </param>
		/// <param name="length">            Length to be Compared from the Starting Point
		/// </param>
		/// <returns> true            Equal
		///				false			Different
		/// *************************************************************************************************** </returns>
		public static bool memoryEqual(byte[] left, int leftOffset, byte[] right, int rightOffset, int length)
		{

			if ((leftOffset + length <= left.Length) && (rightOffset + length <= right.Length))
			{

				for (int i = 0; i < length; i++)
				{

					if (left[leftOffset + i] != right[rightOffset + i])
					{

						return false;

					}

				}

				return true;

			}
			else
			{

				return false;

			}

		}

		/// <summary>
		///**************************************************************************
		/// Description:	Converts 2 Consecutive Bytes in "load" to A Number of "Short"
		///				from A Known Position
		/// </summary>
		/// <param name="load">            Source Array </param>
		/// <param name="loadOffset">        Starting Position
		/// </param>
		/// <returns> A Number of "Short"
		/// *************************************************************************** </returns>
		public static short load16(byte[] load, int loadOffset)
		{

			short number = 0;

			if (load.Length - loadOffset >= (sizeof(short) * 8) / Byte.SIZE)
			{

				for (int i = 0; i < (sizeof(short) * 8) / Byte.SIZE; i++)
				{

					number ^= (short)((short)(load[loadOffset + i] & 0xFF) << (Byte.SIZE * i));

				}

			}
			else
			{

				for (int i = 0; i < load.Length - loadOffset; i++)
				{

					number ^= (short)((short)(load[loadOffset + i] & 0xFF) << (Byte.SIZE * i));

				}

			}

			return number;

		}

		/// <summary>
		///****************************************************************************
		/// Description:	Converts 4 Consecutive Bytes in "load" to A Number of "Integer"
		///				from A Known Position
		/// </summary>
		/// <param name="load">            Source Array </param>
		/// <param name="loadOffset">        Starting Position
		/// </param>
		/// <returns> A Number of "Integer"
		/// ***************************************************************************** </returns>
		public static int load32(byte[] load, int loadOffset)
		{

			int number = 0;

			if (load.Length - loadOffset >= (sizeof(int) * 8) / Byte.SIZE)
			{

				for (int i = 0; i < (sizeof(int) * 8) / Byte.SIZE; i++)
				{

					number ^= (load[loadOffset + i] & 0xFF) << (Byte.SIZE * i);

				}

			}
			else
			{


				for (int i = 0; i < load.Length - loadOffset; i++)
				{

					number ^= (load[loadOffset + i] & 0xFF) << (Byte.SIZE * i);

				}

			}

			return number;

		}

		/// <summary>
		///*************************************************************************
		/// Description:	Converts 8 Consecutive Bytes in "load" to A Number of "Long"
		///				from A Known Position
		/// </summary>
		/// <param name="load">            Source Array </param>
		/// <param name="loadOffset">        Starting Position
		/// </param>
		/// <returns> A Number of "Long"
		/// ************************************************************************** </returns>
		public static long load64(byte[] load, int loadOffset)
		{

			long number = 0L;

			if (load.Length - loadOffset >= (sizeof(long) * 8) / Byte.SIZE)
			{

				for (int i = 0; i < (sizeof(long) * 8) / Byte.SIZE; i++)
				{

					number ^= (long)(load[loadOffset + i] & 0xFF) << (Byte.SIZE * i);

				}

			}
			else
			{

				for (int i = 0; i < load.Length - loadOffset; i++)
				{

					number ^= (long)(load[loadOffset + i] & 0xFF) << (Byte.SIZE * i);

				}

			}

			return number;

		}

		/// <summary>
		///***************************************************************************
		/// Description:	Converts A Number of "Short" to 2 Consecutive Bytes in "store"
		///				from a known position
		/// </summary>
		/// <param name="store">            Destination Array </param>
		/// <param name="storeOffset">        Starting position </param>
		/// <param name="number">            Source Number
		/// </param>
		/// <returns> none
		/// **************************************************************************** </returns>
		public static void store16(byte[] store, int storeOffset, short number)
		{

			if (store.Length - storeOffset >= (sizeof(short) * 8) / Byte.SIZE)
			{

				for (int i = 0; i < (sizeof(short) * 8) / Byte.SIZE; i++)
				{

					store[storeOffset + i] = unchecked((byte)((number >> (Byte.SIZE * i)) & 0xFF));

				}

			}
			else
			{

				for (int i = 0; i < store.Length - storeOffset; i++)
				{

					store[storeOffset + i] = unchecked((byte)((number >> (Byte.SIZE * i)) & 0xFF));

				}

			}

		}

		/// <summary>
		///*****************************************************************************
		/// Description:	Converts A Number of "Integer" to 4 Consecutive Bytes in "store"
		/// 				from A Known Position
		/// </summary>
		/// <param name="store">            Destination Array </param>
		/// <param name="storeOffset">        Starting Position </param>
		/// <param name="number">:			Source Number
		/// </param>
		/// <returns> none
		/// ****************************************************************************** </returns>
		public static void store32(byte[] store, int storeOffset, int number)
		{

			if (store.Length - storeOffset >= (sizeof(int) * 8) / Byte.SIZE)
			{

				for (int i = 0; i < (sizeof(int) * 8) / Byte.SIZE; i++)
				{

					store[storeOffset + i] = unchecked((byte)((number >> (Byte.SIZE * i)) & 0xFF));

				}

			}
			else
			{

				for (int i = 0; i < store.Length - storeOffset; i++)
				{

					store[storeOffset + i] = unchecked((byte)((number >> (Byte.SIZE * i)) & 0xFF));

				}

			}

		}

		/// <summary>
		///**************************************************************************
		/// Description:	Converts A Number of "Long" to 8 Consecutive Bytes in "store"
		/// 				from A Known Position
		/// </summary>
		/// <param name="store">            Destination Array </param>
		/// <param name="storeOffset">        Starting Position </param>
		/// <param name="number">            Source Number
		/// </param>
		/// <returns> none
		/// *************************************************************************** </returns>
		public static void store64(byte[] store, int storeOffset, long number)
		{

			if (store.Length - storeOffset >= (sizeof(long) * 8) / Byte.SIZE)
			{

				for (int i = 0; i < (sizeof(long) * 8) / Byte.SIZE; i++)
				{

					store[storeOffset + i] = unchecked((byte)((number >> (Byte.SIZE * i)) & 0xFFL));

				}

			}
			else
			{

				for (int i = 0; i < store.Length - storeOffset; i++)
				{

					store[storeOffset + i] = unchecked((byte)((number >> (Byte.SIZE * i)) & 0xFFL));

				}

			}

		}

	}
}