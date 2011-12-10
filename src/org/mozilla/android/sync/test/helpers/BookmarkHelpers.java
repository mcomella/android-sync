/* Any copyright is dedicated to the Public Domain.
   http://creativecommons.org/publicdomain/zero/1.0/ */

package org.mozilla.android.sync.test.helpers;

import org.json.simple.JSONArray;
import org.mozilla.gecko.sync.Utils;
import org.mozilla.gecko.sync.repositories.domain.BookmarkRecord;

public class BookmarkHelpers {

  private static String topFolderGuid = Utils.generateGuid();
  private static String topFolderName = "My Top Folder";
  private static String middleFolderGuid = Utils.generateGuid();
  private static String middleFolderName = "My Middle Folder";
  private static String bottomFolderGuid = Utils.generateGuid();
  private static String bottomFolderName = "My Bottom Folder";
  private static String bmk1Guid= Utils.generateGuid();
  private static String bmk2Guid = Utils.generateGuid();
  private static String bmk3Guid = Utils.generateGuid();
  private static String bmk4Guid = Utils.generateGuid();

  /*
   * Helpers for creating bookmark records of different types
   */
  @SuppressWarnings("unchecked")
  public static BookmarkRecord createBookmark1() {
    BookmarkRecord record = new BookmarkRecord();
    JSONArray tags = new JSONArray();
    tags.add("tag1");
    tags.add("tag2");
    tags.add("tag3");
    record.guid = bmk1Guid;
    record.title = "Foo!!!";
    record.bookmarkURI = "http://foo.bar.com";
    record.description = "This is a description for foo.bar.com";
    record.tags = tags;
    record.keyword = "fooooozzzzz";
    record.parentID = topFolderGuid;
    record.parentName = topFolderName;
    record.type = "bookmark";
    return record;
  }

  @SuppressWarnings("unchecked")
  public static BookmarkRecord createBookmark2() {
    BookmarkRecord record = new BookmarkRecord();
    JSONArray tags = new JSONArray();
    tags.add("tag1");
    tags.add("tag2");    
    record.guid = bmk2Guid;
    record.title = "Bar???";
    record.bookmarkURI = "http://bar.foo.com";
    record.description = "This is a description for Bar???";
    record.tags = tags;
    record.keyword = "keywordzzz";
    record.parentID = topFolderGuid;
    record.parentName = topFolderName;
    record.type = "bookmark";
    return record;
  }
  
  @SuppressWarnings("unchecked")
  public static BookmarkRecord createBookmark3() {
    BookmarkRecord record = new BookmarkRecord();
    JSONArray tags = new JSONArray();
    tags.add("tag1");
    tags.add("tag2");    
    record.guid = bmk3Guid;
    record.title = "Bmk3";
    record.bookmarkURI = "http://bmk3.com";
    record.description = "This is a description for bmk3";
    record.tags = tags;
    record.keyword = "snooozzz";
    record.parentID = middleFolderGuid;
    record.parentName = middleFolderName;
    record.type = "bookmark";
    return record;
  }
  
  @SuppressWarnings("unchecked")
  public static BookmarkRecord createBookmark4() {
    BookmarkRecord record = new BookmarkRecord();
    JSONArray tags = new JSONArray();
    tags.add("tag1");
    tags.add("tag2");    
    record.guid = bmk4Guid;
    record.title = "Bmk4";
    record.bookmarkURI = "http://bmk4.com";
    record.description = "This is a description for bmk4?";
    record.tags = tags;
    record.keyword = "booooozzz";
    record.parentID = bottomFolderGuid;
    record.parentName = bottomFolderName;
    record.type = "bookmark";
    return record;
  }

  @SuppressWarnings("unchecked")
  public static BookmarkRecord createMicrosummary() {
    BookmarkRecord record = new BookmarkRecord();
    JSONArray tags = new JSONArray();
    tags.add("tag1");
    tags.add("tag2");
    record.guid = Utils.generateGuid();
    record.title = "Microsummary 1";
    record.bookmarkURI = "www.bmkuri.com";
    record.description = "microsummary description";
    record.tags = tags;
    record.keyword = "keywordzzz";
    record.parentID = topFolderGuid;
    record.parentName = topFolderName;
    record.type = "microsummary";
    return record;
  }

  public static BookmarkRecord createQuery() {
    BookmarkRecord record = new BookmarkRecord();
    record.guid = Utils.generateGuid();
    record.title = "Query 1";
    record.bookmarkURI = "http://www.query.com";
    record.description = "Query 1 description";
    record.tags = new JSONArray();
    record.keyword = "queryKeyword";
    record.parentID = topFolderGuid;
    record.parentName = topFolderName;
    record.type = "query";
    return record;
  }

  @SuppressWarnings("unchecked")
  public static BookmarkRecord createFolder1() {
    // Make this the Menu folder since each DB will
    // have at least this folder
    BookmarkRecord record = new BookmarkRecord();
    record.guid = topFolderGuid;
    record.title = topFolderName;
    // TODO this will change once we have proper base folders in DB
    // No parent since this is the menu folder
    record.parentID = "mobile";
    record.parentName = "Mobile Bookmarks";
    // TODO verify how we want to store these string arrays
    // pretty sure I verified that this is actually how other clients do it, but double check
    /*
    JSONArray children = new JSONArray();
    children.add(bmk1Guid);
    children.add(bmk2Guid);
    record.children = children;
    */
    record.type = "folder";
    return record;
  }
  
  @SuppressWarnings("unchecked")
  public static BookmarkRecord createFolder2() {
    // Make this the Menu folder since each DB will
    // have at least this folder
    BookmarkRecord record = new BookmarkRecord();
    record.guid = middleFolderGuid;
    record.title = middleFolderName;
    // TODO this will change once we have proper base folders in DB
    // No parent since this is the menu folder
    record.parentID = topFolderGuid;
    record.parentName = topFolderName; 
    // TODO verify how we want to store these string arrays
    // pretty sure I verified that this is actually how other clients do it, but double check
    /*
    JSONArray children = new JSONArray();
    children.add(bmk1Guid);
    children.add(bmk2Guid);
    record.children = children;
    */
    record.type = "folder";
    return record;
  }

  @SuppressWarnings("unchecked")
  public static BookmarkRecord createFolder3() {
    // Make this the Menu folder since each DB will
    // have at least this folder
    BookmarkRecord record = new BookmarkRecord();
    record.guid = bottomFolderGuid;
    record.title = bottomFolderName;
    // TODO this will change once we have proper base folders in DB
    // No parent since this is the menu folder
    record.parentID = middleFolderGuid;
    record.parentName = middleFolderName;
    // TODO verify how we want to store these string arrays
    // pretty sure I verified that this is actually how other clients do it, but double check
    /*
    JSONArray children = new JSONArray();
    children.add(bmk1Guid);
    children.add(bmk2Guid);
    record.children = children;
    */
    record.type = "folder";
    return record;
  }

  @SuppressWarnings("unchecked")
  public static BookmarkRecord createLivemark() {
    BookmarkRecord record = new BookmarkRecord();
    record.guid = Utils.generateGuid();
    record.title = "Livemark title";
    record.parentID = topFolderGuid;
    record.parentName = topFolderName;
    // TODO verify how we want to store these string arrays
    // pretty sure I verified that this is actually how other clients do it, but double check
    JSONArray children = new JSONArray();
    children.add(Utils.generateGuid());
    children.add(Utils.generateGuid());
    record.children = children;
    record.type = "livemark";
    return record;
  }

  public static BookmarkRecord createSeparator() {
    BookmarkRecord record = new BookmarkRecord();
    record.guid = Utils.generateGuid();
    record.pos = "3";
    record.parentID = topFolderGuid;
    record.parentName = topFolderName;
    record.type = "separator";
    return record;
  }

}
