/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.gecko.sync;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map.Entry;
import java.util.Set;

import org.json.simple.parser.ParseException;
import org.mozilla.gecko.sync.delegates.InfoCollectionsDelegate;
import org.mozilla.gecko.sync.net.SyncStorageRecordRequest;
import org.mozilla.gecko.sync.net.SyncStorageRequestDelegate;
import org.mozilla.gecko.sync.net.SyncStorageResponse;

import android.util.Log;

public class InfoCollections implements SyncStorageRequestDelegate {
  private static final String LOG_TAG = "InfoCollections";
  protected String infoURL;
  protected String credentials;

  // Fetched objects.
  protected SyncStorageResponse response;
  private ExtendedJSONObject    record;

  // Fields.
  // Rather than storing decimal/double timestamps, as provided by the
  // server, we convert immediately to milliseconds since epoch.
  private HashMap<String, Long> timestamps;

  public HashMap<String, Long> getTimestamps() {
    if (!this.wasSuccessful()) {
      throw new IllegalStateException("No record fetched.");
    }
    return this.timestamps;
  }

  public Long getTimestamp(String collection) {
    return this.getTimestamps().get(collection);
  }

  public boolean wasSuccessful() {
    return this.response.wasSuccessful() &&
           this.timestamps != null;
  }

  // Temporary location to store our callback.
  private InfoCollectionsDelegate callback;

  public InfoCollections(String metaURL, String credentials) {
    this.infoURL     = metaURL;
    this.credentials = credentials;
  }

  public void fetch(InfoCollectionsDelegate callback) {
    if (this.response == null) {
      this.callback = callback;
      this.doFetch();
      return;
    }
    callback.handleSuccess(this);
  }

  private void doFetch() {
    try {
      final SyncStorageRecordRequest r = new SyncStorageRecordRequest(this.infoURL);
      r.delegate = this;
      // TODO: it might be nice to make Resource include its
      // own thread pool, and automatically run asynchronously.
      ThreadPool.run(new Runnable() {
        @Override
        public void run() {
          try {
            r.get();
          } catch (Exception e) {
            callback.handleError(e);
          }
        }});
    } catch (Exception e) {
      callback.handleError(e);
    }
  }

  public SyncStorageResponse getResponse() {
    return this.response;
  }

  protected ExtendedJSONObject ensureRecord() {
    if (record == null) {
      record = new ExtendedJSONObject();
    }
    return record;
  }

  protected void setRecord(ExtendedJSONObject record) {
    this.record = record;
  }

  @SuppressWarnings("unchecked")
  private void unpack(SyncStorageResponse response) throws IllegalStateException, IOException, ParseException, NonObjectJSONException {
    this.response = response;
    this.setRecord(response.jsonObjectBody());
    Log.i(LOG_TAG, "info/collections is " + this.record.toJSONString());
    HashMap<String, Long> map = new HashMap<String, Long>();

    Set<Entry<String, Object>> entrySet = this.record.object.entrySet();
    for (Entry<String, Object> entry : entrySet) {
      // These objects are most likely going to be Doubles. Regardless, we
      // want to get them in a more sane time format.
      String key = entry.getKey();
      Object value = entry.getValue();
      if (value instanceof Double) {
        map.put(key, Utils.decimalSecondsToMilliseconds((Double) value));
        continue;
      }
      if (value instanceof Long) {
        map.put(key, Utils.decimalSecondsToMilliseconds((Long) value));
        continue;
      }
      if (value instanceof Integer) {
        map.put(key, Utils.decimalSecondsToMilliseconds((Integer) value));
        continue;
      }
      Log.w(LOG_TAG, "Skipping info/collections entry for " + key);
    }
    this.timestamps = map;
  }

  // SyncStorageRequestDelegate methods for fetching.
  public String credentials() {
    return this.credentials;
  }

  public String ifUnmodifiedSince() {
    return null;
  }

  public void handleRequestSuccess(SyncStorageResponse response) {
    if (response.wasSuccessful()) {
      try {
        this.unpack(response);
        this.callback.handleSuccess(this);
        this.callback = null;
      } catch (Exception e) {
        this.callback.handleError(e);
        this.callback = null;
      }
      return;
    }
    this.callback.handleFailure(response);
    this.callback = null;
  }

  public void handleRequestFailure(SyncStorageResponse response) {
    this.callback.handleFailure(response);
    this.callback = null;
  }

  public void handleRequestError(Exception e) {
    this.callback.handleError(e);
    this.callback = null;
  }
}
