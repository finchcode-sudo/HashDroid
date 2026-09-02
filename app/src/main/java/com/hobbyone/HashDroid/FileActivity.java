/* FileActivity.java -- 
   Copyright (C) 2010 Christophe Bouyer (Hobby One)

This file is part of Hash Droid.

Hash Droid is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Hash Droid is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Hash Droid. If not, see <http://www.gnu.org/licenses/>.
 */

package com.hobbyone.HashDroid;

import android.app.Activity;
import android.app.ProgressDialog;
import android.content.ActivityNotFoundException;
import android.content.ClipData;
import android.content.Intent;
import android.content.res.Resources;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.provider.OpenableColumns;
import android.text.ClipboardManager;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemSelectedListener;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.LinearLayout;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

public class FileActivity extends Activity implements Runnable {
    private Button mSelectFileButton = null;
    private CheckBox mCheckBox = null;
    private Button mGenerateButton = null;
    private Spinner mSpinner = null;
    private LinearLayout mResultsContainer = null;
    private String[] mFunctions;
    private ClipboardManager mClipboard = null;
    private final int SELECT_FILE_REQUEST = 0;
    private HashFunctionOperator mHashOpe = null;
    private ProgressDialog mProgressDialog = null;
    private int miItePos = -1;
    private List<Uri> mSelectedFileUris = new ArrayList<>();

    // Holds the per-file results computed on the background thread
    private final List<String[]> mFileResults = new ArrayList<>(); // {fileName, fileSizeDisplay, hashOrEmpty}

    /**
     * Called when the activity is first created.
     */
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.file);

        mSelectFileButton = (Button) findViewById(R.id.SelectFileButton);
        mGenerateButton = (Button) findViewById(R.id.GenerateButton);
        mSpinner = (Spinner) findViewById(R.id.spinner);
        mResultsContainer = (LinearLayout) findViewById(R.id.results_container);
        mClipboard = (ClipboardManager) getSystemService("clipboard");
        mFunctions = getResources().getStringArray(R.array.Algo_Array);
        mCheckBox = (CheckBox) findViewById(R.id.UpperCaseCB);

        ArrayAdapter<CharSequence> adapter = ArrayAdapter.createFromResource(
                this, R.array.Algo_Array, android.R.layout.simple_spinner_item);
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        mSpinner.setAdapter(adapter);
        mSpinner.setSelection(6); // MD5 by default

        mSpinner.setOnItemSelectedListener(new OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parentView,
                                       View selectedItemView, int position, long id) {
                if (mResultsContainer != null)
                    mResultsContainer.removeAllViews();
                mFileResults.clear();
            }

            @Override
            public void onNothingSelected(AdapterView<?> parentView) {
            }
        });

        mSelectFileButton.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    Intent openExplorerIntent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
                    openExplorerIntent.addCategory(Intent.CATEGORY_OPENABLE);
                    openExplorerIntent.setType("*/*");
                    openExplorerIntent.putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true);
                    startActivityForResult(Intent.createChooser(openExplorerIntent, "Select file(s)"), SELECT_FILE_REQUEST);
                } catch (ActivityNotFoundException e) {
                }
            }
        });

        mGenerateButton.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View v) {
                if (!mSelectedFileUris.isEmpty()) {
                    miItePos = mSpinner.getSelectedItemPosition();
                    ComputeAndDisplayHash();
                }
            }
        });

        mCheckBox.setChecked(false); // lower case by default
        mCheckBox.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View v) {
                // Re-render with the new case if results already exist
                if (!mFileResults.isEmpty()) {
                    RenderResult();
                }
            }
        });
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == SELECT_FILE_REQUEST && resultCode == RESULT_OK) {
            mSelectedFileUris.clear();
            if (data != null) {
                if (data.getClipData() != null) {
                    // Multiple files selected
                    ClipData clipData = data.getClipData();
                    for (int i = 0; i < clipData.getItemCount(); i++) {
                        mSelectedFileUris.add(clipData.getItemAt(i).getUri());
                    }
                } else if (data.getData() != null) {
                    // Single file selected
                    mSelectedFileUris.add(data.getData());
                }
            }
            if (!mSelectedFileUris.isEmpty()) {
                if (mSelectedFileUris.size() == 1) {
                    String ret = getFileName(mSelectedFileUris.get(0));
                    mSelectFileButton.setText(ret);
                } else {
                    mSelectFileButton.setText(String.format(
                            getString(R.string.files_selected), mSelectedFileUris.size()));
                }
            }
        }
    }

    private String getFileName(Uri uri) {
        String name = "";
        Cursor cursor = getContentResolver().query(uri, null, null, null, null);
        if (cursor != null && cursor.moveToFirst()) {
            int idx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
            if (idx >= 0)
                name = cursor.getString(idx);
            cursor.close();
        }
        return name;
    }

    private long getFileSize(Uri uri) {
        long size = -1;
        Cursor cursor = getContentResolver().query(uri, null, null, null, null);
        if (cursor != null && cursor.moveToFirst()) {
            int idx = cursor.getColumnIndex(OpenableColumns.SIZE);
            if (idx >= 0)
                size = cursor.getLong(idx);
            cursor.close();
        }
        return size;
    }

    private void ComputeAndDisplayHash() {
        if (mHashOpe == null)
            mHashOpe = new HashFunctionOperator();
        String sAlgo = "";
        if (miItePos == 0)
            sAlgo = "Adler-32";
        else if (miItePos == 1)
            sAlgo = "blake2b-512";
        else if (miItePos == 2)
            sAlgo = "CRC-32";
        else if (miItePos == 3)
            sAlgo = "Haval";
        else if (miItePos == 4)
            sAlgo = "md2";
        else if (miItePos == 5)
            sAlgo = "md4";
        else if (miItePos == 6)
            sAlgo = "md5";
        else if (miItePos == 7)
            sAlgo = "ripemd-128";
        else if (miItePos == 8)
            sAlgo = "ripemd-160";
        else if (miItePos == 9)
            sAlgo = "sha-1";
        else if (miItePos == 10)
            sAlgo = "sha-224";
        else if (miItePos == 11)
            sAlgo = "sha-256";
        else if (miItePos == 12)
            sAlgo = "sha-384";
        else if (miItePos == 13)
            sAlgo = "sha-512";
        else if (miItePos == 14)
            sAlgo = "sha3-256";
        else if (miItePos == 15)
            sAlgo = "sha3-512";
        else if (miItePos == 16)
            sAlgo = "sm3";
        else if (miItePos == 17)
            sAlgo = "tiger";
        else if (miItePos == 18)
            sAlgo = "whirlpool";
        mHashOpe.SetAlgorithm(sAlgo);

        String sCalculating = getString(R.string.Calculating);
        mProgressDialog = ProgressDialog.show(FileActivity.this, "",
                sCalculating, true);

        Thread thread = new Thread(this);
        thread.start();
    }

    @Override
    // Call when the thread is started
    public void run() {
        mFileResults.clear();

        for (Uri uri : mSelectedFileUris) {
            String fileName = getFileName(uri);
            long size = getFileSize(uri);
            String sizeDisplay = size >= 0 ? FileSizeDisplay(size, false) : "";
            String hash = "";

            if (mHashOpe != null) {
                InputStream inputStream = null;
                try {
                    inputStream = getContentResolver().openInputStream(uri);
                } catch (FileNotFoundException e1) {
                }
                if (null != inputStream) {
                    hash = mHashOpe.FileToHash(inputStream);
                }
            }
            mFileResults.add(new String[]{fileName, sizeDisplay, hash});
        }
        handler.sendEmptyMessage(0);
    }

    private String FileSizeDisplay(long lbytes, boolean bSI) {
        int unit = bSI ? 1000 : 1024;
        if (lbytes < unit)
            return lbytes + " B";
        int exp = (int) (Math.log(lbytes) / Math.log(unit));
        String pre = (bSI ? "kMGTPE" : "KMGTPE").charAt(exp - 1)
                + (bSI ? "" : "i");
        return String.format("%.2f %sB", lbytes / Math.pow(unit, exp), pre);
    }

    // Rebuilds one result row per file, each with its own copy button.
    private void RenderResult() {
        Resources res = getResources();
        boolean upper = mCheckBox != null && mCheckBox.isChecked();
        String Function = (miItePos >= 0 && miItePos < mFunctions.length) ? mFunctions[miItePos] : "";

        if (mResultsContainer != null)
            mResultsContainer.removeAllViews();

        LayoutInflater inflater = getLayoutInflater();

        for (String[] entry : mFileResults) {
            String fileName = entry[0];
            String sizeDisplay = entry[1];
            String hash = entry[2];

            String sFileNameTitle = String.format(res.getString(R.string.FileName), fileName);
            String sFileSizeTitle = String.format(res.getString(R.string.FileSize), sizeDisplay);
            String sFileHashTitle;
            final String copyPayload;

            if (!hash.equals("")) {
                String displayHash = upper ? hash.toUpperCase() : hash.toLowerCase();
                sFileHashTitle = String.format(res.getString(R.string.Hash), Function, displayHash);
                copyPayload = displayHash;
            } else {
                sFileHashTitle = String.format(res.getString(R.string.unable_to_calculate), fileName);
                copyPayload = null;
            }

            View row = inflater.inflate(R.layout.file_result_row, mResultsContainer, false);
            TextView rowText = (TextView) row.findViewById(R.id.row_result_text);
            Button rowCopyButton = (Button) row.findViewById(R.id.row_copy_button);

            rowText.setText(sFileNameTitle + sFileSizeTitle + sFileHashTitle);

            if (copyPayload != null) {
                rowCopyButton.setVisibility(View.VISIBLE);
                rowCopyButton.setOnClickListener(new OnClickListener() {
                    @Override
                    public void onClick(View v) {
                        if (mClipboard != null) {
                            mClipboard.setText(copyPayload);
                            Toast.makeText(FileActivity.this, getString(R.string.copied),
                                    Toast.LENGTH_SHORT).show();
                        }
                    }
                });
            } else {
                rowCopyButton.setVisibility(View.GONE);
            }

            if (mResultsContainer != null)
                mResultsContainer.addView(row);
        }
    }

    // This method is called when the computation is over
    private Handler handler = new Handler() {
        @Override
        public void handleMessage(Message msg) {
            if (mProgressDialog != null)
                mProgressDialog.dismiss();
            RenderResult();
        }
    };
}
