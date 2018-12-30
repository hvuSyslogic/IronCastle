using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.util
{
	/// <summary>
	/// An interface defining a list of strings.
	/// </summary>
	public interface StringList : Iterable<string>
	{
		/// <summary>
		/// Add a String to the list.
		/// </summary>
		/// <param name="s"> the String to add. </param>
		/// <returns> true </returns>
		bool add(string s);

		/// <summary>
		/// Get the string at index index.
		/// </summary>
		/// <param name="index"> the index position of the String of interest. </param>
		/// <returns> the String at position index. </returns>
		string get(int index);

		int size();

		/// <summary>
		/// Return the contents of the list as an array.
		/// </summary>
		/// <returns> an array of String. </returns>
		string[] toStringArray();

		/// <summary>
		/// Return a section of the contents of the list. If the list is too short the array is filled with nulls.
		/// </summary>
		/// <param name="from"> the initial index of the range to be copied, inclusive </param>
		/// <param name="to"> the final index of the range to be copied, exclusive. </param>
		/// <returns> an array of length to - from </returns>
		string[] toStringArray(int from, int to);
	}

}