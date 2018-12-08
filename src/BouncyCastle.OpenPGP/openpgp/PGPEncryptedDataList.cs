using org.bouncycastle.bcpg;

namespace org.bouncycastle.openpgp
{

	using BCPGInputStream = org.bouncycastle.bcpg.BCPGInputStream;
	using InputStreamPacket = org.bouncycastle.bcpg.InputStreamPacket;
	using PacketTags = org.bouncycastle.bcpg.PacketTags;
	using PublicKeyEncSessionPacket = org.bouncycastle.bcpg.PublicKeyEncSessionPacket;
	using SymmetricKeyEncSessionPacket = org.bouncycastle.bcpg.SymmetricKeyEncSessionPacket;
	using Iterable = org.bouncycastle.util.Iterable;

	/// <summary>
	/// A holder for a list of PGP encryption method packets and the encrypted data associated with them.
	/// <para>
	/// This holder supports reading a sequence of the following encryption methods, followed by an
	/// encrypted data packet:</para>
	/// <ul>
	/// <li><seealso cref="PacketTags#SYMMETRIC_KEY_ENC_SESSION"/> - produces a <seealso cref="PGPPBEEncryptedData"/></li>
	/// <li><seealso cref="PacketTags#PUBLIC_KEY_ENC_SESSION"/> - produces a <seealso cref="PGPPublicKeyEncryptedData"/></li>
	/// </ul>
	/// <para>
	/// All of the objects returned from this holder share a reference to the same encrypted data input
	/// stream, which can only be consumed once.
	/// </para>
	/// </summary>
	public class PGPEncryptedDataList : Iterable
	{
		internal List list = new ArrayList();
		internal InputStreamPacket data;

		/// <summary>
		/// Construct an encrypted data packet holder, reading PGP encrypted method packets and an
		/// encrytped data packet from the stream.
		/// <para>
		/// The next packet in the stream should be one of <seealso cref="PacketTags#SYMMETRIC_KEY_ENC_SESSION"/>
		/// or <seealso cref="PacketTags#PUBLIC_KEY_ENC_SESSION"/>.
		/// </para> </summary>
		/// <param name="pIn"> the PGP object stream being read. </param>
		/// <exception cref="IOException"> if an error occurs reading from the PGP input. </exception>
		public PGPEncryptedDataList(BCPGInputStream pIn)
		{
			while (pIn.nextPacketTag() == PacketTags_Fields.PUBLIC_KEY_ENC_SESSION || pIn.nextPacketTag() == PacketTags_Fields.SYMMETRIC_KEY_ENC_SESSION)
			{
				list.add(pIn.readPacket());
			}

			data = (InputStreamPacket)pIn.readPacket();

			for (int i = 0; i != list.size(); i++)
			{
				if (list.get(i) is SymmetricKeyEncSessionPacket)
				{
					list.set(i, new PGPPBEEncryptedData((SymmetricKeyEncSessionPacket)list.get(i), data));
				}
				else
				{
					list.set(i, new PGPPublicKeyEncryptedData((PublicKeyEncSessionPacket)list.get(i), data));
				}
			}
		}

		/// <summary>
		/// Gets the encryption method object at the specified index.
		/// </summary>
		/// <param name="index"> the encryption method to obtain (0 based). </param>
		public virtual object get(int index)
		{
			return list.get(index);
		}

		/// <summary>
		/// Gets the number of encryption methods in this list.
		/// </summary>
		public virtual int size()
		{
			return list.size();
		}

		/// <summary>
		/// Returns <code>true</code> iff there are 0 encryption methods in this list.
		/// </summary>
		public virtual bool isEmpty()
		{
			return list.isEmpty();
		}

		/// <summary>
		/// Returns an iterator over the encryption method objects held in this list, in the order they
		/// appeared in the stream they are read from.
		/// </summary>
		public virtual Iterator getEncryptedDataObjects()
		{
			return list.iterator();
		}

		/// <summary>
		/// Support method for Iterable where available.
		/// </summary>
		public virtual Iterator iterator()
		{
			return getEncryptedDataObjects();
		}
	}

}